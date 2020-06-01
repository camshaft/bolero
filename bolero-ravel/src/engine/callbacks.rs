// ATTRIBUTE_INTERFACE
// void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop) {
//   fuzzer::TPC.HandleInline8bitCountersInit(Start, Stop);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_8bit_counters_init(_start: *const u8, _stop: *const u8) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
//                               const uintptr_t *pcs_end) {
//   fuzzer::TPC.HandlePCsInit(pcs_beg, pcs_end);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_pcs_init(_start: *const usize, _stop: *const usize) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// void __sanitizer_cov_trace_pc_indir(uintptr_t Callee) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCallerCallee(PC, Callee);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_pc_indir(_callee: *const u8) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp8(_a: u64, _b: u64) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// // Now the __sanitizer_cov_trace_const_cmp[1248] callbacks just mimic
// // the behaviour of __sanitizer_cov_trace_cmp[1248] ones. This, however,
// // should be changed later to make full use of instrumentation.
// void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp8(_a: u64, _b: u64) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp4(_a: u32, _b: u32) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp4(_a: u32, _b: u32) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp2(_a: u16, _b: u16) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp2(_a: u16, _b: u16) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp1(_a: u8, _b: u8) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp1(_a: u8, _b: u8) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases) {
//   uint64_t N = Cases[0];
//   uint64_t ValSizeInBits = Cases[1];
//   uint64_t *Vals = Cases + 2;
//   // Skip the most common and the most boring case: all switch values are small.
//   // We may want to skip this at compile-time, but it will make the
//   // instrumentation less general.
//   if (Vals[N - 1]  < 256)
//     return;
//   // Also skip small inputs values, they won't give good signal.
//   if (Val < 256)
//     return;
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   size_t i;
//   uint64_t Smaller = 0;
//   uint64_t Larger = ~(uint64_t)0;
//   // Find two switch values such that Smaller < Val < Larger.
//   // Use 0 and 0xfff..f as the defaults.
//   for (i = 0; i < N; i++) {
//     if (Val < Vals[i]) {
//       Larger = Vals[i];
//       break;
//     }
//     if (Val > Vals[i]) Smaller = Vals[i];
//   }

//   // Apply HandleCmp to {Val,Smaller} and {Val, Larger},
//   // use i as the PC modifier for HandleCmp.
//   if (ValSizeInBits == 16) {
//     fuzzer::TPC.HandleCmp(PC + 2 * i, static_cast<uint16_t>(Val),
//                           (uint16_t)(Smaller));
//     fuzzer::TPC.HandleCmp(PC + 2 * i + 1, static_cast<uint16_t>(Val),
//                           (uint16_t)(Larger));
//   } else if (ValSizeInBits == 32) {
//     fuzzer::TPC.HandleCmp(PC + 2 * i, static_cast<uint32_t>(Val),
//                           (uint32_t)(Smaller));
//     fuzzer::TPC.HandleCmp(PC + 2 * i + 1, static_cast<uint32_t>(Val),
//                           (uint32_t)(Larger));
//   } else {
//     fuzzer::TPC.HandleCmp(PC + 2*i, Val, Smaller);
//     fuzzer::TPC.HandleCmp(PC + 2*i + 1, Val, Larger);
//   }
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_switch(_value: u64, _cases: *const u64) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_div4(uint32_t Val) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Val, (uint32_t)0);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_div4(_value: u32) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_div8(uint64_t Val) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Val, (uint64_t)0);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_div8(_value: u64) {
    // TODO
}

// ATTRIBUTE_INTERFACE
// ATTRIBUTE_NO_SANITIZE_ALL
// ATTRIBUTE_TARGET_POPCNT
// void __sanitizer_cov_trace_gep(uintptr_t Idx) {
//   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
//   fuzzer::TPC.HandleCmp(PC, Idx, (uintptr_t)0);
// }

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_gep(_idx: *const u8) {
    // TODO
}
