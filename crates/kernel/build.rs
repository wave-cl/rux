fn main() {
    let target = std::env::var("TARGET").unwrap();

    if target.contains("x86_64") {
        println!("cargo:rustc-link-arg=-T");
        println!("cargo:rustc-link-arg=crates/kernel/linker-x86_64.ld");
        println!("cargo:rustc-link-arg=--gc-sections");
        println!("cargo:rustc-link-arg=--no-pie");
    } else if target.contains("aarch64") {
        println!("cargo:rustc-link-arg=-T");
        println!("cargo:rustc-link-arg=crates/kernel/linker-aarch64.ld");
        println!("cargo:rustc-link-arg=--gc-sections");
        println!("cargo:rustc-link-arg=--no-pie");
    }

    println!("cargo:rerun-if-changed=linker-x86_64.ld");
    println!("cargo:rerun-if-changed=linker-aarch64.ld");
    println!("cargo:rerun-if-changed=src/x86_64/boot.S");
}
