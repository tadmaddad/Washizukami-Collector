fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    println!("cargo:rerun-if-changed=assets/washi.ico");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Absolute path to the icon so windres can find it regardless of CWD.
    let icon_path = format!("{}/assets/washi.ico", manifest_dir).replace('\\', "/");
    let rc_path   = format!("{}/resource.rc", out_dir);
    let o_path    = format!("{}/resource.o", out_dir);

    // Write a minimal .rc file embedding just the icon.
    std::fs::write(&rc_path, format!("1 ICON \"{}\"\n", icon_path))
        .expect("failed to write resource.rc");

    // Compile with windres (MinGW).  windres must be on PATH.
    let status = std::process::Command::new("windres")
        .args(["--input", &rc_path, "--output", &o_path, "--output-format=coff"])
        .status()
        .expect("windres not found — ensure C:\\msys64\\mingw64\\bin is on PATH");

    if !status.success() {
        panic!("windres failed to compile resource.rc");
    }

    // Link the object file directly (not as a static lib).
    // cargo:rustc-link-lib=static would let GNU ld drop the .rsrc section
    // because it has no exported symbols.  Passing the .o directly forces it in.
    println!("cargo:rustc-link-arg={}", o_path);
}
