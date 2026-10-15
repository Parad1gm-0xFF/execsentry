//! Agent de surveillance d'exécution Linux, côté utilisateur.
//!
//! Charge le programme eBPF `execsentry`, l'attache au tracepoint noyau
//! `syscalls/sys_enter_execve`, puis consomme le ring buffer d'événements pour
//! signaler les exécutions suspectes. Nécessite les privilèges root (`CAP_BPF`).

use std::{
    io,
    mem::size_of,
    os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, anyhow};
use aya::{
    Ebpf,
    maps::{MapData, PerCpuArray, ring_buf::RingBuf},
    programs::TracePoint,
};
use clap::Parser;
use execsentry_common::ExecEvent;
use tokio::io::{Interest, unix::AsyncFd};

mod policy;
use policy::classify;

/// Intervalle maximal sans notification avant une vidange de sécurité du ring.
const DRAIN_INTERVAL: Duration = Duration::from_millis(100);

/// `perf_event_attr.type` pour un événement tracepoint.
const PERF_TYPE_TRACEPOINT: u32 = 2;
/// `perf_event_open` : fermer le fd à l'exec.
const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;
/// `ioctl` : associer un programme eBPF à un événement perf.
const PERF_EVENT_IOC_SET_BPF: u64 = 0x4008_2408;
/// `ioctl` : activer l'événement perf.
const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;

#[derive(Debug, Parser)]
#[command(
    name = "execsentry",
    version,
    about = "Agent eBPF de surveillance des exécutions (tracepoint sys_enter_execve)"
)]
struct Opt {
    /// Affiche aussi les exécutions jugées normales.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    bump_memlock_rlimit();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/execsentry"
    )))
    .context("chargement de l'objet eBPF")?;

    let program: &mut TracePoint = ebpf
        .program_mut("execsentry")
        .ok_or_else(|| anyhow!("programme eBPF 'execsentry' introuvable"))?
        .try_into()?;
    program.load()?;
    // `TracePoint::attach` d'aya n'attache que le CPU 0 : on attache nous-mêmes le
    // programme à un événement perf par CPU, pour couvrir toute la machine.
    let prog_fd = program.fd()?.as_fd().as_raw_fd();
    let tp_id = tracepoint_id("syscalls", "sys_enter_execve")?;
    let _perf_fds = attach_tracepoint_all_cpus(prog_fd, tp_id)
        .context("attache du tracepoint syscalls/sys_enter_execve sur tous les CPU")?;

    let events = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("map 'EVENTS' introuvable"))?;
    let ring = RingBuf::try_from(events)?;
    let exec_total = PerCpuArray::<MapData, u64>::try_from(ebpf.take_map("EXEC_TOTAL").unwrap())?;
    let exec_dropped =
        PerCpuArray::<MapData, u64>::try_from(ebpf.take_map("EXEC_DROPPED").unwrap())?;

    // SAFETY: `register_with_interest` exige que le fd appartienne à `T` et reste
    // vivant : c'est le cas, `AsyncFd` prend possession du `RingBuf` et le garde.
    let mut async_fd = unsafe { AsyncFd::register_with_interest(ring, Interest::READABLE)? };

    let shutdown = Arc::new(AtomicBool::new(false));
    spawn_ctrl_c_handler(Arc::clone(&shutdown));

    banner();

    let mut received: u64 = 0;
    let mut alerts: u64 = 0;

    while !shutdown.load(Ordering::Relaxed) {
        match tokio::time::timeout(DRAIN_INTERVAL, async_fd.readable_mut()).await {
            Ok(guard) => {
                let mut guard = guard?;
                drain(
                    guard.get_inner_mut(),
                    opt.verbose,
                    &mut received,
                    &mut alerts,
                );
                guard.clear_ready();
            }
            // Aucune notification dans l'intervalle : vidange de sécurité, pour ne
            // jamais laisser le ring se remplir et perdre des événements.
            Err(_) => drain(async_fd.get_mut(), opt.verbose, &mut received, &mut alerts),
        }
    }

    let observed = per_cpu_sum(&exec_total)?;
    let dropped = per_cpu_sum(&exec_dropped)?;

    println!("\nexecsentry arrêté : {received} reçues, {alerts} alertes.");
    println!("Noyau : {observed} execve observés, {dropped} jetés (ring saturé).");
    Ok(())
}

/// Vide tout le ring buffer disponible et met à jour les compteurs.
fn drain(ring: &mut RingBuf<MapData>, verbose: bool, received: &mut u64, alerts: &mut u64) {
    while let Some(item) = ring.next() {
        if let Some(event) = decode(&item) {
            *received += 1;
            if report(&event, verbose) {
                *alerts += 1;
            }
        }
    }
}

/// Réinterprète les octets d'une entrée de ring buffer en [`ExecEvent`].
fn decode(bytes: &[u8]) -> Option<ExecEvent> {
    if bytes.len() < size_of::<ExecEvent>() {
        return None;
    }
    // SAFETY: `ExecEvent` est `#[repr(C)]`, sans padding et composé d'entiers
    // (contrat `aya::Pod`) ; le ring buffer aligne les entrées sur 8 octets.
    // `read_unaligned` reste correct même si cette garantie venait à manquer.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<ExecEvent>()) })
}

/// Affiche un événement ; retourne `true` s'il a déclenché une alerte.
fn report(event: &ExecEvent, verbose: bool) -> bool {
    let comm = String::from_utf8_lossy(event.comm());
    let filename = String::from_utf8_lossy(event.filename());
    let path: &str = if filename.is_empty() {
        "<inconnu>"
    } else {
        &filename
    };

    match classify(event) {
        Some(finding) => {
            println!(
                "[{}] pid={} uid={} comm={} path={} ({})",
                finding.severity.label(),
                event.pid,
                event.uid,
                comm,
                path,
                finding
            );
            true
        }
        None => {
            if verbose {
                println!(
                    "[    ok    ] pid={} uid={} comm={} path={}",
                    event.pid, event.uid, comm, path
                );
            }
            false
        }
    }
}

/// Somme une carte `PerCpuArray` sur l'ensemble des CPU.
fn per_cpu_sum(map: &PerCpuArray<MapData, u64>) -> anyhow::Result<u64> {
    Ok(map.get(&0u32, 0)?.iter().copied().sum())
}

/// Enregistre un gestionnaire Ctrl-C qui positionne le drapeau d'arrêt.
fn spawn_ctrl_c_handler(shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.store(true, Ordering::Relaxed);
        }
    });
}

/// Construit un `perf_event_attr` brut pour un événement tracepoint.
///
/// On écrit les champs par offset plutôt que de reproduire la structure noyau
/// (dont les champs de bits sont fragiles) : le noyau ne lit que les octets
/// couverts par `size`.
fn perf_attr_tracepoint(id: u64) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    bytes[0..4].copy_from_slice(&PERF_TYPE_TRACEPOINT.to_ne_bytes()); // type
    bytes[4..8].copy_from_slice(&128u32.to_ne_bytes()); // size
    bytes[8..16].copy_from_slice(&id.to_ne_bytes()); // config
    bytes[16..24].copy_from_slice(&1u64.to_ne_bytes()); // sample_period
    bytes[40..48].copy_from_slice(&1u64.to_ne_bytes()); // disabled = 1 (bit 0)
    bytes[48..52].copy_from_slice(&1u32.to_ne_bytes()); // wakeup_events
    bytes
}

/// Lit l'identifiant d'un tracepoint dans tracefs.
fn tracepoint_id(category: &str, name: &str) -> anyhow::Result<u64> {
    for base in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let path = format!("{base}/events/{category}/{name}/id");
        if let Ok(id) = std::fs::read_to_string(&path) {
            return id
                .trim()
                .parse()
                .context("identifiant de tracepoint invalide");
        }
    }
    anyhow::bail!("tracepoint {category}/{name} introuvable (tracefs monté ?)")
}

/// Attache un programme tracepoint à un événement perf par CPU.
///
/// Nécessaire car `aya::programs::TracePoint::attach` n'ouvre un `perf_event` que
/// pour le CPU 0. Retourne les fd à conserver pendant la surveillance.
fn attach_tracepoint_all_cpus(prog_fd: RawFd, id: u64) -> anyhow::Result<Vec<OwnedFd>> {
    let cpus = aya::util::online_cpus().map_err(|(_, err)| anyhow!(err))?;
    let mut fds = Vec::new();
    for cpu in cpus {
        let attr = perf_attr_tracepoint(id);
        let raw = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                attr.as_ptr().cast::<libc::c_void>(),
                -1_i32,     // pid : tous les processus
                cpu as i32, // cpu
                -1_i32,     // groupe
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("perf_event_open sur le CPU {cpu}"));
        }
        // SAFETY: `raw` vient d'être retourné par `perf_event_open`, on en prend
        // possession de façon exclusive.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };

        if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_SET_BPF, prog_fd) } < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("PERF_EVENT_IOC_SET_BPF sur le CPU {cpu}"));
        }
        if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0) } < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("PERF_EVENT_IOC_ENABLE sur le CPU {cpu}"));
        }
        fds.push(fd);
    }
    Ok(fds)
}

fn banner() {
    println!(
        "execsentry v{} — agent eBPF de surveillance des exécutions",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "Tracepoint : syscalls/sys_enter_execve. Signalement des exécutions suspectes. Ctrl-C pour quitter.\n"
    );
}

/// Lève la limite `RLIMIT_MEMLOCK` pour les anciens noyaux à comptabilité rlimit.
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("note : impossible de lever RLIMIT_MEMLOCK (sans conséquence sur noyau récent).");
    }
}
