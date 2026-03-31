fn main() {
    let target = std::env::var("TARGET").unwrap();

    // Only apply bare-metal linker scripts when targeting *-unknown-none.
    // The native test harness (--features native) targets aarch64-apple-darwin
    // or x86_64-unknown-linux-gnu and uses the platform's default linker.
    if target.ends_with("-unknown-none") || target.ends_with("-none-eabi") {
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
    }

    println!("cargo:rerun-if-changed=linker-x86_64.ld");
    println!("cargo:rerun-if-changed=linker-aarch64.ld");
    println!("cargo:rerun-if-changed=src/x86_64/boot.S");
}
