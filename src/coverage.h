//
//  coverage.h
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#ifndef coverage_h
#define coverage_h

// Define _XOPEN_SOURCE before including ucontext.h
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

// Include sys/types.h before sys/sysctl.h to get u_int, u_char, etc.
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>

#define MAP_SIZE 0x10000

void updateCoverage(uint64_t curLoc);
extern uint16_t previousLoc;

#ifdef __cplusplus
extern "C" {
#endif

void installHandlers(void);
void libFuzzerCleanUp(void);

#ifdef __cplusplus
}
#endif

#endif /* coverage_h */
