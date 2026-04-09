use std::path::PathBuf;
use std::process::Command;

fn main() {
    // 1. Build the Lean formal project (includes FFI exports)
    let lean_project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../formal");
    let status = Command::new("lake")
        .arg("build")
        .arg("EthLambda")
        .current_dir(&lean_project)
        .status()
        .expect("Failed to run `lake build`. Is elan/lake on PATH?");
    assert!(status.success(), "lake build failed");

    // 2. Find Lean installation
    let lean_prefix = String::from_utf8(
        Command::new("lean")
            .arg("--print-prefix")
            .output()
            .expect("Failed to run `lean --print-prefix`")
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();

    let lean_include = format!("{lean_prefix}/include");
    let lean_lib = format!("{lean_prefix}/lib/lean");
    let lean_dep_lib = format!("{lean_prefix}/lib");

    // 3. Compile the EthLambda C IR + glue into a static archive.
    //    No Mathlib in the impl lib, so only our files are needed.
    let ir_dir = lean_project.join(".lake/build/ir");
    cc::Build::new()
        .file(ir_dir.join("EthLambda.c"))
        .file(ir_dir.join("EthLambda/Justifiability.c"))
        .file("src/lean_glue.c")
        .include(&lean_include)
        .opt_level(2)
        .compile("leanffi");

    // 4. Link the Lean runtime statically (self-contained binary)
    println!("cargo:rustc-link-search=native={lean_lib}");
    println!("cargo:rustc-link-search=native={lean_dep_lib}");
    println!("cargo:rustc-link-lib=static=leanrt");
    println!("cargo:rustc-link-lib=static=Init");
    println!("cargo:rustc-link-lib=static=gmp");
    println!("cargo:rustc-link-lib=static=uv");
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }

    // 5. Rebuild triggers
    println!("cargo:rerun-if-changed=../../formal/EthLambda/Justifiability.lean");
    println!("cargo:rerun-if-changed=src/lean_glue.c");
}
