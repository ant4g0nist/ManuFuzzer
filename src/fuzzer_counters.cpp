//
//  fuzzer_counters.cpp
//  ManuFuzzer
//
//  Created for ManuFuzzer
//

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// size of the coverage map (must match size in FuzzerExtraCountersDarwin.cpp)
#define PCS_N (1 << 16)

// global LibFuzzCounters array that will be used by both
// the coverage instrumentation and libFuzzer's ExtraCounters functions
extern "C" uint8_t *LibFuzzCounters = nullptr;

// Initialize function that will be called during startup
__attribute__((constructor))
static void initializeLibFuzzCounters() {
    if (LibFuzzCounters == nullptr) {
        // Allocate memory for the counters - using aligned memory
        // for better performance with coverage tracking
        #ifdef __APPLE__
        posix_memalign((void**)&LibFuzzCounters, 64, PCS_N);
        #else
        LibFuzzCounters = new uint8_t[PCS_N];
        #endif

        // Initialize all counters to zero
        memset(LibFuzzCounters, 0, PCS_N);
    }
}

// Cleanup function that will be called during shutdown
__attribute__((destructor))
static void cleanupLibFuzzCounters() {
    if (LibFuzzCounters != nullptr) {
        #ifdef __APPLE__
        free(LibFuzzCounters);
        #else
        delete[] LibFuzzCounters;
        #endif
        LibFuzzCounters = nullptr;
    }
}
