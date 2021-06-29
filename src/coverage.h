//
//  coverage.h
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#ifndef coverage_h
#define coverage_h

#include <stdint.h>
#include <signal.h>

#define MAP_SIZE (1 << 16)

extern "C" int libFuzzerCleanUp();
extern "C" void installHandlers();

#endif /* coverage_h */
