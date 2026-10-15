use which::which;

/// La compilation de cette crate dépend de façon non déclarée du binaire
/// `bpf-linker`. On force cargo à recompiler si le chemin de `bpf-linker` change.
fn main() {
    let bpf_linker = which("bpf-linker")
        .expect("bpf-linker introuvable dans le PATH (installe-le : `cargo install bpf-linker`)");
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
