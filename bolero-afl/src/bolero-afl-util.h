#include "../afl/types.h"

static u64 parsed_afl_max_cycles = 0;

static u64 bolero_afl_max_cycles() {
    if (!parsed_afl_max_cycles) {
        u8* max_cycles = getenv("BOLERO_AFL_MAX_CYCLES");

        if (sscanf(max_cycles, "%llu", &parsed_afl_max_cycles) < 1) {
            // set a default
            parsed_afl_max_cycles = 100;
        }
    }

    return parsed_afl_max_cycles;
}
