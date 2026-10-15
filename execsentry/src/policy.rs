//! Politique de détection côté utilisateur.
//!
//! Logique pure (aucune E/S) pour rester testable : on transforme un
//! [`ExecEvent`] brut en une éventuelle alerte graduée.

use execsentry_common::ExecEvent;
use std::fmt;

/// Répertoires où l'exécution directe de binaires est anormale : volatils,
/// inscriptibles par tous, souvent utilisés pour déposer puis lancer un payload.
const VOLATILE_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/run/user/"];

/// Outils « living off the land » et interpréteurs fréquemment détournés
/// (exfiltration, reverse shell, téléchargement exécuté).
const DUAL_USE_BINARIES: &[&str] = &[
    "nc",
    "ncat",
    "netcat",
    "socat",
    "mkfifo",
    "base64",
    "xxd",
    "openssl",
    "curl",
    "wget",
    "chisel",
    "proxychains",
    "ssh",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "bash",
    "sh",
    "dash",
    "zsh",
];

/// Gravité d'une alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Suspicious,
    Critical,
}

impl Severity {
    /// Étiquette affichable.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Suspicious => "SUSPICIOUS",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// Motif expliquant l'alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Le binaire est exécuté depuis un répertoire volatil et inscriptible.
    VolatilePath,
    /// L'exécution a lieu sous l'UID 0 (root).
    RootExecution,
    /// Nom de binaire à double usage (shell, outil réseau, interpréteur).
    DualUseBinary,
}

impl Reason {
    fn label(self) -> &'static str {
        match self {
            Reason::VolatilePath => "chemin volatil/inscriptible",
            Reason::RootExecution => "exécution en root (uid 0)",
            Reason::DualUseBinary => "binaire à double usage (shell/LOTL)",
        }
    }
}

/// Résultat de l'analyse : une gravité et la liste des motifs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub reasons: Vec<Reason>,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reasons: Vec<&str> = self.reasons.iter().map(|r| r.label()).collect();
        write!(f, "{}", reasons.join(", "))
    }
}

/// Analyse un événement d'exécution. Retourne `None` si rien d'anormal n'est vu.
pub fn classify(event: &ExecEvent) -> Option<Finding> {
    let path = String::from_utf8_lossy(event.filename());
    if path.is_empty() {
        return None;
    }
    let base = basename(&path);

    let is_volatile =
        path.starts_with('/') && VOLATILE_PREFIXES.iter().any(|p| path.starts_with(p));
    let is_dual_use = DUAL_USE_BINARIES.contains(&base);
    let is_root = event.uid == 0;

    let mut reasons = Vec::new();
    if is_volatile {
        reasons.push(Reason::VolatilePath);
    }
    if is_dual_use {
        reasons.push(Reason::DualUseBinary);
    }
    if is_root && is_volatile {
        reasons.push(Reason::RootExecution);
    }

    let severity = if is_volatile && (is_dual_use || is_root) {
        Severity::Critical
    } else if is_volatile {
        Severity::Suspicious
    } else if is_root && is_dual_use {
        // root lançant un shell/outil double usage reste notable, mais très courant.
        return None;
    } else {
        return None;
    };

    Some(Finding { severity, reasons })
}

/// Dernier composant du chemin (nom du binaire), sans dépendre de `std::path`
/// pour gérer proprement le cas d'un chemin vide.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(path: &str, uid: u32) -> ExecEvent {
        let mut ev = ExecEvent {
            timestamp_ns: 0,
            pid: 100,
            tgid: 100,
            uid,
            gid: uid,
            comm: [0u8; execsentry_common::COMM_LEN],
            filename: [0u8; execsentry_common::FILENAME_LEN],
        };
        let bytes = path.as_bytes();
        ev.filename[..bytes.len()].copy_from_slice(bytes);
        ev
    }

    #[test]
    fn benign_system_binary() {
        assert_eq!(classify(&event("/usr/bin/ls", 1000)), None);
    }

    #[test]
    fn benign_dual_use_outside_volatile_path() {
        // Un curl légitime depuis /usr/bin ne doit pas alerter.
        assert_eq!(classify(&event("/usr/bin/curl", 1000)), None);
    }

    #[test]
    fn volatile_path_is_suspicious() {
        let finding = classify(&event("/tmp/loader", 1000)).unwrap();
        assert_eq!(finding.severity, Severity::Suspicious);
        assert_eq!(finding.reasons, vec![Reason::VolatilePath]);
    }

    #[test]
    fn volatile_path_with_shell_is_critical() {
        let finding = classify(&event("/dev/shm/nc", 1000)).unwrap();
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.reasons.contains(&Reason::VolatilePath));
        assert!(finding.reasons.contains(&Reason::DualUseBinary));
    }

    #[test]
    fn root_from_volatile_path_is_critical() {
        let finding = classify(&event("/tmp/payload", 0)).unwrap();
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.reasons.contains(&Reason::RootExecution));
    }

    #[test]
    fn empty_path_is_ignored() {
        assert_eq!(classify(&event("", 0)), None);
    }

    #[test]
    fn basename_handles_trailing_and_no_slash() {
        assert_eq!(basename("/usr/bin/ls"), "ls");
        assert_eq!(basename("nc"), "nc");
        assert_eq!(basename(""), "");
    }
}
