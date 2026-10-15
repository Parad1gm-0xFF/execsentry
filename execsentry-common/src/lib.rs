#![no_std]
//! Types partagés entre le programme eBPF (noyau) et le chargeur userspace.
//!
//! Ces types doivent rester « layout-compatible » des deux côtés : `#[repr(C)]`,
//! pas de padding implicite, uniquement des entiers et des tableaux d'octets.

/// Longueur de `comm` (nom de tâche noyau), cf. `TASK_COMM_LEN` dans `linux/sched.h`.
pub const COMM_LEN: usize = 16;

/// Longueur maximale du chemin exécuté conservé dans l'événement.
pub const FILENAME_LEN: usize = 256;

/// Événement d'exécution (`execve`) remonté du noyau vers l'espace utilisateur.
///
/// `repr(C)` + champs POD : la représentation mémoire est identique sur la cible
/// eBPF et sur l'hôte x86_64/aarch64, ce qui autorise une lecture directe dans le
/// ring buffer. Pas de padding : 8 octets alignés (u64 en tête).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// Horodatage noyau, monotone (`bpf_ktime_get_ns`), en nanosecondes.
    pub timestamp_ns: u64,
    /// PID (thread) de la tâche qui appelle `execve`.
    pub pid: u32,
    /// TGID (groupe de threads / PID « utilisateur ») de la tâche.
    pub tgid: u32,
    /// UID réel effectif de la tâche.
    pub uid: u32,
    /// GID réel effectif de la tâche.
    pub gid: u32,
    /// Nom de tâche (`comm`) au moment de l'appel, terminé par NUL si plus court.
    pub comm: [u8; COMM_LEN],
    /// Chemin du binaire exécuté, terminé par NUL si plus court que la taille maximale.
    pub filename: [u8; FILENAME_LEN],
}

impl ExecEvent {
    /// `comm` sans le NUL terminal, sous forme de tranche d'octets.
    pub fn comm(&self) -> &[u8] {
        cstr_bytes(&self.comm)
    }

    /// `filename` sans le NUL terminal, sous forme de tranche d'octets.
    pub fn filename(&self) -> &[u8] {
        cstr_bytes(&self.filename)
    }
}

/// Tranche d'octets s'arrêtant au premier NUL (ou à la fin du tampon).
fn cstr_bytes(buf: &[u8]) -> &[u8] {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..end]
}

// `Pod` (plain old data) est le contrat attendu par aya pour lire un type depuis un
// ring buffer. Sûr ici : `#[repr(C)]`, sans padding, constitué uniquement d'entiers.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
