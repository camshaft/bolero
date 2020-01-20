#include <stdbool.h>
#include "dtrace_provider.h"

void bolero_instrument_dtrace(bool enabled) {
    if (enabled) {
        if (BOLERO_INSTRUMENT_START_ENABLED()) {
            BOLERO_INSTRUMENT_START();
        }
    } else {
        if (BOLERO_INSTRUMENT_STOP_ENABLED()) {
            BOLERO_INSTRUMENT_STOP();
        }
    }
}
