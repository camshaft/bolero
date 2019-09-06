#include "../libfuzzer/FuzzerDefs.h"

extern "C" {
    // external user defined function
    int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

    int LLVMFuzzerStartTest(int argc, char **argv) {
        return fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
    }
}
