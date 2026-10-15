//! Agent de surveillance d'exécution Linux, côté utilisateur.
//!
//! Charge le programme eBPF `execsentry`, l'attache au tracepoint noyau
//! `syscalls/sys_enter_execve`, puis consomme le ring buffer d'événements pour
//! signaler les exécutions suspectes. Nécessite les privilèges root (`CAP_BPF`).

use std::mem::size_of;

use anyhow::{Context as _, anyhow};
use aya::{Ebpf, maps::ring_buf::RingBuf, programs::TracePoint};
use clap::Parser;
use execsentry_common::ExecEvent;
use tokio::io::{Interest, unix::AsyncFd};

mod policy;
use policy::classify;

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
    program
        .attach("syscalls", "sys_enter_execve")
        .context("attache du tracepoint syscalls/sys_enter_execve")?;

    let map = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("map 'EVENTS' introuvable"))?;
    let ring = RingBuf::try_from(map)?;
    // SAFETY: `register_with_interest` exige que le fd appartienne à `T` et reste
    // vivant : c'est le cas, `AsyncFd` prend possession du `RingBuf` et le garde.
    let mut async_fd = unsafe { AsyncFd::register_with_interest(ring, Interest::READABLE)? };

    banner();

    let mut total: u64 = 0;
    let mut alerts: u64 = 0;

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal?;
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    if let Some(event) = decode(&item) {
                        total += 1;
                        if report(&event, opt.verbose) {
                            alerts += 1;
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    println!("\nexecsentry arrêté : {total} exécutions observées, {alerts} alertes.");
    Ok(())
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
