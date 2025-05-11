//
//  coverage.mm
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#include <sys/types.h>  // For u_int, u_char, etc.
#include <string.h>     // For strerror
#include "coverage.h"
#include "utilities.h"
#include <mach/vm_page_size.h>
#include <libkern/OSCacheControl.h>
#include <Foundation/Foundation.h>

// ARM64 macros to access thread state fields
#define __darwin_arm_thread_state64_get_pc(ts) \
    ((ts).__pc)
#define __darwin_arm_thread_state64_get_lr(ts) \
    ((ts).__lr)
#define __darwin_arm_thread_state64_get_sp(ts) \
    ((ts).__sp)
#define __darwin_arm_thread_state64_get_fp(ts) \
    ((ts).__fp)
#define __darwin_arm_thread_state64_set_pc(ts, val) \
    ((ts).__pc = (val))

extern task_t task;
uint16_t previousLoc = 0;
extern uint8_t *LibFuzzCounters; // Defined in FuzzerCounters.cpp

extern void sys_icache_invalidate( void *start, size_t len);

void dump_registers(ucontext_t* uc)
{
    printf( "\n"
    "x0:%016lx x1:%016lx x2:%016lx x3:%016lx\n"
    "x4:%016lx x5:%016lx x6:%016lx x7:%016lx\n"
    "x8:%016lx x9:%016lx x10:%016lx x11:%016lx\n"
    "x12:%016lx x13:%016lx x14:%016lx x15:%016lx\n"
    "x16:%016lx x17:%016lx x18:%016lx x19:%016lx\n"
    "x20:%016lx x21:%016lx x22:%016lx x23:%016lx\n"
    "x24:%016lx x25:%016lx x26:%016lx x27:%016lx\n"
    "x28:%016lx fp:%016lx lr:%016lx\n"
    "sp:%016lx pc:%016lx cpsr:%08lx\n",
        (unsigned long) uc->uc_mcontext->__ss.__x[0],
        (unsigned long) uc->uc_mcontext->__ss.__x[1],
        (unsigned long) uc->uc_mcontext->__ss.__x[2],
        (unsigned long) uc->uc_mcontext->__ss.__x[3],
        (unsigned long) uc->uc_mcontext->__ss.__x[4],
        (unsigned long) uc->uc_mcontext->__ss.__x[5],
        (unsigned long) uc->uc_mcontext->__ss.__x[6],
        (unsigned long) uc->uc_mcontext->__ss.__x[7],
        (unsigned long) uc->uc_mcontext->__ss.__x[8],
        (unsigned long) uc->uc_mcontext->__ss.__x[9],
        (unsigned long) uc->uc_mcontext->__ss.__x[10],
        (unsigned long) uc->uc_mcontext->__ss.__x[11],
        (unsigned long) uc->uc_mcontext->__ss.__x[12],
        (unsigned long) uc->uc_mcontext->__ss.__x[13],
        (unsigned long) uc->uc_mcontext->__ss.__x[14],
        (unsigned long) uc->uc_mcontext->__ss.__x[15],
        (unsigned long) uc->uc_mcontext->__ss.__x[16],
        (unsigned long) uc->uc_mcontext->__ss.__x[17],
        (unsigned long) uc->uc_mcontext->__ss.__x[18],
        (unsigned long) uc->uc_mcontext->__ss.__x[19],
        (unsigned long) uc->uc_mcontext->__ss.__x[20],
        (unsigned long) uc->uc_mcontext->__ss.__x[21],
        (unsigned long) uc->uc_mcontext->__ss.__x[22],
        (unsigned long) uc->uc_mcontext->__ss.__x[23],
        (unsigned long) uc->uc_mcontext->__ss.__x[24],
        (unsigned long) uc->uc_mcontext->__ss.__x[25],
        (unsigned long) uc->uc_mcontext->__ss.__x[26],
        (unsigned long) uc->uc_mcontext->__ss.__x[27],
        (unsigned long) uc->uc_mcontext->__ss.__x[28],
        (unsigned long) __darwin_arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
        (unsigned long) __darwin_arm_thread_state64_get_lr(uc->uc_mcontext->__ss),
        (unsigned long) __darwin_arm_thread_state64_get_sp(uc->uc_mcontext->__ss),
        (unsigned long) __darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss),
        (unsigned long) uc->uc_mcontext->__ss.__cpsr);
}

//TODO: AFL's Blindspot and How to Resist AFL Fuzzing for Arbitrary ELF Binaries
void updateCoverage(uint64_t curLoc)
{
    uint64_t originalCurLoc = curLoc;
    curLoc  = ( (curLoc >> 4) ^ (curLoc << 8) ) & (MAP_SIZE - 1);
    uint16_t map_idx = curLoc ^ previousLoc;

    // Ensure LibFuzzCounters is not null before dereferencing
    if (LibFuzzCounters) {
        dlogn("[Coverage] updateCoverage: originalCurLoc=0x%llx, calculatedIndex=0x%x (curLoc=0x%llx ^ prevLoc=0x%x), CounterValueBefore=%d",
        originalCurLoc, map_idx, curLoc, previousLoc, LibFuzzCounters[map_idx]);
        LibFuzzCounters[map_idx]++;
        dlogn("[Coverage] updateCoverage: CounterValueAfter=%d", LibFuzzCounters[map_idx]);
    } else {
        dlogn("[Coverage] updateCoverage: LibFuzzCounters is NULL. originalCurLoc=0x%llx, calculatedIndex=0x%x",
        originalCurLoc, map_idx);
    }
    previousLoc = (uint16_t)(curLoc >> 1);
}

// Global map to track shadow memory regions for each module
#include <map>
struct ShadowRegion {
    uint64_t moduleBase;
    uint64_t shadowBase;
    size_t size;
};
static std::map<uint64_t, ShadowRegion> g_shadow_regions;

// Function to register shadow memory mapping
extern "C" void registerShadowMapping(uint64_t moduleBase, uint64_t shadowBase, size_t size) {
    ShadowRegion region = {moduleBase, shadowBase, size};
    g_shadow_regions[moduleBase] = region;
    dlogn("Registered shadow mapping: module=0x%llx -> shadow=0x%llx, size=%zu",
          moduleBase, shadowBase, size);
}

// Function to find shadow address for a given code address
static void* findShadowAddress(void* addr) {
    uint64_t code_addr = (uint64_t)addr;

    // Find the shadow region this address belongs to
    for (const auto& entry : g_shadow_regions) {
        uint64_t moduleBase = entry.first;
        const ShadowRegion& region = entry.second;

        if (code_addr >= moduleBase && code_addr < moduleBase + region.size) {
            // Calculate offset within module
            uint64_t offset = code_addr - moduleBase;
            // Calculate shadow address
            uint64_t shadow_addr = region.shadowBase + offset;
            dlogn("Found shadow for 0x%llx: module=0x%llx, offset=0x%llx, shadow=0x%llx",
                  code_addr, moduleBase, offset, shadow_addr);
            return (void*)shadow_addr;
        }
    }

    dlogn("WARNING: No shadow mapping found for address 0x%llx", code_addr);
    // Return NULL instead of using fallback calculation
    return NULL;
}

static void coverageHandler(int signum, siginfo_t* info, void* context)
{
    dlogn("[Coverage] coverageHandler invoked for signal %d", signum);

    ucontext_t* uc = (ucontext_t*)context;

    uint32_t* fault_addr = (uint32_t*)info->si_addr;

    // Find the correct shadow address using our mapping
    uint32_t *shadow = (uint32_t*)findShadowAddress(fault_addr);

    if (shadow == NULL) {
        dlogn("ERROR: No shadow mapping for address %p, skipping", fault_addr);
        // If we don't have a shadow mapping, we need to skip this instruction
        // to avoid getting stuck
        __darwin_arm_thread_state64_set_pc(uc->uc_mcontext->__ss,
            __darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss) + 4);
        return;
    }

    dlogn("coverage_handler: fault_addr : %p shadowAddr : %p", fault_addr, shadow);

    updateCoverage((uint64_t) fault_addr);

    if (mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_WRITE) != 0) {
        dlogn("ERROR: Failed to mprotect %p writable: %s", fault_addr, strerror(errno));
        // Skip the instruction to avoid infinite loop
        __darwin_arm_thread_state64_set_pc(uc->uc_mcontext->__ss,
            __darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss) + 4);
        return;
    }

    uint32_t orig_byte = *shadow;
    dlogn("orig_byte: %x", orig_byte);

    // Verify that the original instruction is valid (non-zero)
    if (orig_byte == 0) {
        dlogn("ERROR: Shadow memory contains zero at %p for fault address %p", shadow, fault_addr);
        // Replace the breakpoint with a NOP instruction to avoid infinite loop
        *fault_addr = 0xd503201f; // NOP instruction on ARM64

        sys_icache_invalidate(fault_addr, 4);
        __asm__ volatile("dmb ishst" ::: "memory");

        // Restore original protection
        mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_EXEC);
        return;
    }

    *fault_addr = orig_byte;

    sys_icache_invalidate(fault_addr, 4);
    __asm__ volatile("dmb ishst" ::: "memory");

    if (mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_EXEC) != 0) {
        dlogn("ERROR: Failed to mprotect %p executable: %s", fault_addr, strerror(errno));
    }

    dlogn("== coverageHandler end");
}

extern "C" void installHandlers()
{
    dlogn("Installing handlers");

    struct sigaction s;
    s.sa_flags = SA_SIGINFO;
    s.sa_sigaction = coverageHandler;

    sigemptyset(&s.sa_mask);
    sigaction(SIGTRAP, &s, 0);

    // LibFuzzCounters is now managed by LibFuzzer
    // We don't need to initialize or clear it here

    dlogn("Installed handlers");
}

extern "C" void libFuzzerCleanUp()
{
    // LibFuzzCounters is managed by LibFuzzer, no cleanup needed here
}
