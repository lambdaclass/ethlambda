fn main() {
    // Compile the RISC-V guest program so `include_elf!("zkvm_guest_sp1")` can
    // embed its ELF. Path is relative to this crate's manifest directory.
    sp1_build::build_program("../../guest-program/sp1");
}
