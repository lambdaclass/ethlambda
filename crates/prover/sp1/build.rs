use sp1_build::{BuildArgs, build_program_with_args};

fn main() {
    // Compile the RISC-V guest program so `include_elf!("zkvm_guest_sp1")` can
    // embed its ELF. Path is relative to this crate's manifest directory.
    //
    // `ignore_rust_version` removes the compatibility issues with the toolchain
    // being used for ethlambda and the sp1 toolchain
    let args = BuildArgs {
        ignore_rust_version: true,
        ..Default::default()
    };
    build_program_with_args("../../guest-program/sp1", args);
}
