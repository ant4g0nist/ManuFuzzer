//
//  coverage.mm
//  ManuFuzzer
//
//  Created by ant4g0nist
//  Improved version with better organization and error handling
//

#include "coverage.h"
#include "utilities.h"
#include <mach/vm_page_size.h>
#include <libkern/OSCacheControl.h>
#include <Foundation/Foundation.h>
#include <errno.h>

////////////////////////////////////////////////////////////////////////////////
// Global Variables & Constants
////////////////////////////////////////////////////////////////////////////////

extern task_t task;
 uint16_t previousLoc = 0;
uint8_t *LibFuzzCounters = nullptr;

// Constants for coverage tracking
static constexpr uint32_t BRK_INSTRUCTION = 0xd4200000 | (1 << 5);
static constexpr size_t REGISTER_BUFFER_SIZE = 1024;

////////////////////////////////////////////////////////////////////////////////
// Type Definitions
////////////////////////////////////////////////////////////////////////////////

// Structure to hold register dump information
struct RegisterDump {
    uint64_t x[29];     // x0-x28
    uint64_t fp;        // Frame pointer
    uint64_t lr;        // Link register
    uint64_t sp;        // Stack pointer
    uint64_t pc;        // Program counter
    uint64_t cpsr;      // Current program status register
};

////////////////////////////////////////////////////////////////////////////////
// Register Handling
////////////////////////////////////////////////////////////////////////////////

static void formatRegisterOutput(char* buffer, size_t bufferSize, const RegisterDump& regs) {
    snprintf(buffer, bufferSize,
        "\n"
        "x0:%016lx x1:%016lx x2:%016lx x3:%016lx\n"
        "x4:%016lx x5:%016lx x6:%016lx x7:%016lx\n"
        "x8:%016lx x9:%016lx x10:%016lx x11:%016lx\n"
        "x12:%016lx x13:%016lx x14:%016lx x15:%016lx\n"
        "x16:%016lx x17:%016lx x18:%016lx x19:%016lx\n"
        "x20:%016lx x21:%016lx x22:%016lx x23:%016lx\n"
        "x24:%016lx x25:%016lx x26:%016lx x27:%016lx\n"
        "x28:%016lx fp:%016lx lr:%016lx\n"
        "sp:%016lx pc:%016lx cpsr:%08lx\n",
        regs.x[0], regs.x[1], regs.x[2], regs.x[3],
        regs.x[4], regs.x[5], regs.x[6], regs.x[7],
        regs.x[8], regs.x[9], regs.x[10], regs.x[11],
        regs.x[12], regs.x[13], regs.x[14], regs.x[15],
        regs.x[16], regs.x[17], regs.x[18], regs.x[19],
        regs.x[20], regs.x[21], regs.x[22], regs.x[23],
        regs.x[24], regs.x[25], regs.x[26], regs.x[27],
        regs.x[28], regs.fp, regs.lr,
        regs.sp, regs.pc, regs.cpsr
    );
}

static void extractRegisters(const ucontext_t* uc, RegisterDump& regs) {
    for (int i = 0; i < 29; i++) {
        regs.x[i] = uc->uc_mcontext->__ss.__x[i];
    }
    
    regs.fp = arm_thread_state64_get_fp(uc->uc_mcontext->__ss);
    regs.lr = arm_thread_state64_get_lr(uc->uc_mcontext->__ss);
    regs.sp = arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
    regs.pc = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    regs.cpsr = uc->uc_mcontext->__ss.__cpsr;
}

void dump_registers(ucontext_t* uc) {
    RegisterDump regs;
    extractRegisters(uc, regs);
    
    char buffer[REGISTER_BUFFER_SIZE];
    formatRegisterOutput(buffer, REGISTER_BUFFER_SIZE, regs);
    printf("%s", buffer);
}

////////////////////////////////////////////////////////////////////////////////
// Coverage Tracking
////////////////////////////////////////////////////////////////////////////////

static bool setMemoryProtection(void* addr, size_t size, int prot) {
    if (mprotect(addr, size, prot) != 0) {
        dlogn("Failed to set memory protection: %s", strerror(errno));
        return false;
    }
    return true;
}

void updateCoverage(uint64_t curLoc) {
    // Hash the current location to get an index into the coverage map
    curLoc = ((curLoc >> 4) ^ (curLoc << 8)) & (MAP_SIZE - 1);
    
    // Update coverage counters using the current and previous locations
    LibFuzzCounters[curLoc ^ previousLoc]++;
    
    // Update previous location for next coverage update
    previousLoc = previousLoc >> 1;
}

////////////////////////////////////////////////////////////////////////////////
// Signal Handling
////////////////////////////////////////////////////////////////////////////////

static bool handleMemoryAccess(uint32_t* fault_addr, uint32_t* shadow) {
    // Make the faulting page writable
    if (!setMemoryProtection((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_WRITE)) {
        return false;
    }

    // Restore original instruction from shadow memory
    uint32_t orig_byte = *shadow;
    *fault_addr = orig_byte;

    // Ensure cache coherency
    sys_icache_invalidate(fault_addr, 4);
    __asm__ volatile("dmb ishst" ::: "memory");

    // Restore execute permissions
    if (!setMemoryProtection((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_EXEC)) {
        return false;
    }

    return true;
}

static void coverageHandler(int signum, siginfo_t* info, void* context) {
    dlogn("== coverageHandler start");

    uint32_t* fault_addr = (uint32_t*)info->si_addr;
    uint32_t* shadow = (uint32_t*)shadowMeUp(fault_addr);
    
    dlogn("coverage_handler: fault_addr: %llx shadowAddr: %llx", fault_addr, shadow);
    
    // Update coverage information
    updateCoverage((uint64_t)fault_addr);
    
    // Handle the memory access and instruction restoration
    if (!handleMemoryAccess(fault_addr, shadow)) {
        fatal("Failed to handle memory access at address %p", fault_addr);
    }

    dlogn("== coverageHandler end");
}

////////////////////////////////////////////////////////////////////////////////
// Initialization and Cleanup
////////////////////////////////////////////////////////////////////////////////

static bool initializeCoverageCounters() {
    LibFuzzCounters = (uint8_t*)malloc(sizeof(uint8_t) * MAP_SIZE);
    if (!LibFuzzCounters) {
        dlogn("Failed to allocate coverage counters");
        return false;
    }
    
    memset(LibFuzzCounters, 0, sizeof(uint8_t) * MAP_SIZE);
    return true;
}

static bool setupSignalHandler() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = coverageHandler;
    
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGTRAP, &sa, nullptr) != 0) {
        dlogn("Failed to set up signal handler: %s", strerror(errno));
        return false;
    }
    
    return true;
}

extern "C" void installHandlers() {
    dlogn("Installing handlers");
    
    if (!setupSignalHandler()) {
        fatal("Failed to install signal handler");
    }
    
    if (!initializeCoverageCounters()) {
        fatal("Failed to initialize coverage counters");
    }
    
    dlogn("Installed handlers");
}

extern "C" int libFuzzerCleanUp() {
    if (LibFuzzCounters) {
        free(LibFuzzCounters);
        LibFuzzCounters = nullptr;
    }
    return 0;
}