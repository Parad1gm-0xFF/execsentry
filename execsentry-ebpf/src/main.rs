#![no_std]
#![no_main]
//! Programme eBPF de l'agent : `fentry` sur `__x64_sys_execve`.
//!
//! `fentry` (BPF trampoline) s'attache via un seul lien couvrant **tous** les CPU,
//! contrairement aux tracepoints attachés par `perf_event` (un par CPU, refusés
//! quand on réutilise le même programme). Le contexte est la fonction hookée :
//! `__x64_sys_execve(struct pt_regs *regs)`.

use aya_ebpf::{
    bindings::pt_regs,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{fentry, map},
    maps::{PerCpuArray, RingBuf},
    programs::FEntryContext,
};
use execsentry_common::{COMM_LEN, ExecEvent, FILENAME_LEN};

/// Ring buffer de sortie (doit être une puissance de 2 multiple de la page).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Nombre total d'`execve` vus par le programme noyau (par CPU).
#[map]
static EXEC_TOTAL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Nombre d'événements jetés faute de place dans le ring buffer (par CPU).
#[map]
static EXEC_DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[cfg(not(bpf_target_arch = "x86_64"))]
compile_error!("execsentry cible x86_64 : hook `__x64_sys_execve` (adapter pour une autre arch).");

#[fentry(function = "__x64_sys_execve")]
pub fn execsentry(ctx: FEntryContext) -> u32 {
    try_execsentry(ctx).unwrap_or(0)
}

fn try_execsentry(ctx: FEntryContext) -> Result<u32, u32> {
    // Premier argument de `__x64_sys_execve(struct pt_regs *regs)`.
    let regs_ptr = ctx.arg::<*const pt_regs>(0);
    if regs_ptr.is_null() {
        return Err(1);
    }
    let regs = unsafe { bpf_probe_read_kernel(regs_ptr) }.map_err(|_| 2u32)?;
    // `rdi` = premier argument du syscall `execve` : le chemin cible (user).
    let filename_ptr = regs.rdi as *const u8;

    increment(&EXEC_TOTAL);

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let mut event = ExecEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: (pid_tgid & 0xffff_ffff) as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: (uid_gid & 0xffff_ffff) as u32,
        gid: (uid_gid >> 32) as u32,
        comm: [0u8; COMM_LEN],
        filename: [0u8; FILENAME_LEN],
    };

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    // Échec possible (chaîne très longue, faute de page) : on remonte quand même
    // l'événement, avec un `filename` vide ou tronqué.
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        entry.write(event);
        entry.submit(0);
    } else {
        increment(&EXEC_DROPPED);
    }

    Ok(0)
}

/// Incrémente un compteur `PerCpuArray<u64>` d'une unité (au plus une entrée).
fn increment(map: &PerCpuArray<u64>) {
    if let Some(ptr) = map.get_ptr_mut(0) {
        unsafe { *ptr += 1 };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
