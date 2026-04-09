/* Wraps Lean's static-inline helpers into real symbols for Rust FFI. */
#include <lean/lean.h>

void lean_ffi_dec_ref(lean_object *o) { lean_dec_ref(o); }
