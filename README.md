# execsentry

> Agent de sécurité Linux en **Rust** + **eBPF** : il s'attache au tracepoint
> noyau `syscalls/sys_enter_execve`, capture chaque exécution de programme
> (identité de la tâche, `comm`, chemin du binaire lu en mémoire utilisateur) et
> signale les exécutions suspectes.

Projet ciblé pour fermer les deux écarts d'un poste « Linux Security Engineer »
(eBPF / Rust de production) : le développement d'un **agent de sécurité eBPF** et
l'écriture de **Rust système**, côté noyau (`no_std`) comme côté utilisateur.

---

## Ce que le projet montre

| Compétence visée | Preuve dans ce dépôt |
|---|---|
| Programmation eBPF en **Rust** | Programme `no_std` + `no_main` (aya-ebpf), macro `#[tracepoint]` |
| Attachement bas niveau | Tracepoint noyau `syscalls/sys_enter_execve` (offsets de `pt_regs`) |
| Lecture mémoire utilisateur | `bpf_probe_read_user_str_bytes` du chemin `filename` |
| Ring buffer noyau -> user | `RingBuf` côté eBPF, consommation `epoll`/`AsyncFd` côté Rust |
| Rust système | Loader `aya`, `#[repr(C)]` partagé, `Pod`, `read_unaligned` |
| Contrats partagés | Crate `execsentry-common` compilée à la fois pour `bpfel` et pour l'hôte |
| Politique de détection | Module `policy` pur, testé unitairement (7 tests) |

---

## Architecture

```
execsentry-common/   Types partagés (ExecEvent #[repr(C)], contrat Pod)
execsentry-ebpf/     Programme eBPF (no_std) : tracepoint sys_enter_execve -> RingBuf
execsentry/          Chargeur userspace : aya + tokio (AsyncFd), politique de détection
```

Flux : `execve` -> tracepoint -> programme eBPF -> `ExecEvent` dans le ring buffer
-> chargeur Rust -> classification (bénin / SUSPICIOUS / CRITICAL) -> sortie.

## Règles de détection

- **SUSPICIOUS** : binaire exécuté depuis un répertoire volatil et inscriptible
  (`/tmp`, `/var/tmp`, `/dev/shm`, `/run`, `/run/user`).
- **CRITICAL** : chemin volatil ET (binaire à double usage OU exécution en root) ;
  ou binaire à double usage (shell, `nc`, `socat`, `curl`, interpréteurs...) lancé
  depuis un répertoire volatil.
- Le reste n'est pas signalé, sauf en mode `--verbose`.

Les règles vivent dans `execsentry/src/policy.rs` et sont couvertes par des tests
(`cargo test`).

---

## Prérequis

- Rust **nightly** + composant `rust-src` (cible `bpfel-unknown-none`, `-Z build-std`).
  Le fichier `rust-toolchain.toml` épingle la toolchain ; rustup l'installe seul.
- **bpf-linker** : soit le binaire précompilé des releases
  (<https://github.com/aya-rs/bpf-linker/releases>), soit `cargo install bpf-linker`.
- Noyau avec `CONFIG_DEBUG_INFO_BTF`, `CONFIG_BPF_SYSCALL` (4.19+ recommandé) et
  privilèges root / `CAP_BPF` pour charger le programme.

## Compiler

```bash
cargo build --release
```

Le `build.rs` du chargeur compile automatiquement le programme eBPF (via
`aya-build`) et l'objet résultant est embarqué dans le binaire par
`include_bytes_aligned!`.

## Exécuter

```bash
# nécessite root (CAP_BPF)
sudo ./target/release/execsentry           # n'affiche que les alertes
sudo ./target/release/execsentry --verbose # affiche aussi les exécutions normales
```

Un terminal d'exemple pour provoquer des événements :

```bash
./scripts/demo.sh
```

## Tests et qualité

```bash
cargo test                 # 7 tests unitaires (politique de détection)
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

---

## Limites assumées

- Le programme s'attache à `sys_enter_execve` (événement à l'entrée de l'appel),
  pas à un hook LSM : pas de blocage possible, on observe. Un hook LSM eBPF
  (`lsm/bprm_check_security`) serait la suite logique mais exige `lsm=bpf` au boot.
- `comm` est le nom de tâche **avant** `exec` (donc le programme appelant).
- La séparation `comm`/`filename` et l'absence d'`argv` limitent la finesse de la
  détection (une vraie solution lirait `argv` et suivrait la filiation).
- Pas encore de persistance, de métriques ni d'export (Syslog/OTel).

## Licence

MIT OR Apache-2.0.
