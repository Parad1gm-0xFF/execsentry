#![no_std]
#![no_main]
//! Programme eBPF de l'agent : tracepoint noyau `syscalls/sys_enter_execve`.
//!
//! À chaque appel système `execve`, le programme capture l'identité de la tâche
//! (pid/tgid, uid/gid), son `comm` et le chemin du binaire cible (lu depuis la
//! mémoire utilisateur avec `bpf_probe_read_user_str_bytes`), puis publie un
//! [`ExecEvent`] dans un ring buffer consommé par le chargeur userspace.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use execsentry_common::{COMM_LEN, ExecEvent, FILENAME_LEN};

/// Ring buffer de sortie (doit être une puissance de 2 multiple de la page).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 256, 0);

/// Dans le format du tracepoint `sys_enter_execve`, `filename` est le 1er argument,
/// situé à l'offset 16 (8 octets d'en-tête commun + 4 d'`__syscall_nr` + 4 de padding).
const FILENAME_ARG_OFFSET: usize = 16;

#[tracepoint]
pub fn execsentry(ctx: TracePointContext) -> u32 {
    try_execsentry(ctx).unwrap_or(0)
}

fn try_execsentry(ctx: TracePointContext) -> Result<u32, u32> {
    // Pointeur vers la chaîne `filename` en mémoire utilisateur.
    let filename_ptr =
        unsafe { ctx.read_at::<*const u8>(FILENAME_ARG_OFFSET) }.map_err(|_| 1u32)?;

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
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
