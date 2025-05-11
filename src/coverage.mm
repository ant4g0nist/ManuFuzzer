//
// Coverage.mm
//
// Manufuzzer

#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <atomic>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include "coverage.h"
#include "utilities.h"
#include <mach/vm_page_size.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <Foundation/Foundation.h>

// ARM64 macros
#define __darwin_arm_thread_state64_get_pc(ts) ((ts).__pc)
#define __darwin_arm_thread_state64_set_pc(ts, val) ((ts).__pc = (val))

// Reduced shadow mapping size for memory efficiency
#define MAX_SHADOW_REGIONS 128

struct ShadowMapping {
    uint64_t module_base;
    uint64_t module_end;
    uint64_t shadow_base;
    uint32_t module_index;
    bool valid;
};

// Global state
static ShadowMapping g_shadow_mappings[MAX_SHADOW_REGIONS];
static std::atomic<int> g_num_mappings{0};
static std::atomic<bool> g_coverage_enabled{false};
static std::atomic<uint16_t> g_previous_loc{0};

// Memory pools for shadow regions
static struct {
    void* base;
    size_t size;
    size_t used;
} g_shadow_pool = {nullptr, 0, 0};

extern uint8_t *LibFuzzCounters;
extern task_t task;
extern void sys_icache_invalidate(void *start, size_t len);

// Initialize shadow memory pool
static bool initializeShadowPool() {
    // Pre-allocate a large shadow memory pool (256MB)
    const size_t POOL_SIZE = 256 * 1024 * 1024;
    g_shadow_pool.base = mmap(nullptr, POOL_SIZE,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (g_shadow_pool.base == MAP_FAILED) {
        return false;
    }

    g_shadow_pool.size = POOL_SIZE;
    g_shadow_pool.used = 0;
    return true;
}

// Allocate from shadow pool instead of individual mmap calls
static void* allocateFromShadowPool(size_t size) {
    // Align size to page boundary
    size = (size + vm_page_size - 1) & ~(vm_page_size - 1);

    if (g_shadow_pool.used + size > g_shadow_pool.size) {
        return nullptr; // Pool exhausted
    }

    void* result = (char*)g_shadow_pool.base + g_shadow_pool.used;
    g_shadow_pool.used += size;
    return result;
}

// Register shadow mapping with pool allocation
extern "C" void registerShadowMapping(uint64_t moduleBase, uint64_t shadowBase, size_t size) {
    int idx = g_num_mappings.fetch_add(1, std::memory_order_release);
    if (idx >= MAX_SHADOW_REGIONS) {
        g_num_mappings.fetch_sub(1, std::memory_order_release);
        return;
    }

    g_shadow_mappings[idx] = {
        .module_base = moduleBase,
        .module_end = moduleBase + size,
        .shadow_base = shadowBase,
        .module_index = (uint32_t)idx,
        .valid = true
    };

    dlogn("Shadow mapping %d: module=0x%llx-0x%llx -> shadow=0x%llx",
          idx, moduleBase, moduleBase + size, shadowBase);
}

// Optimized shadow address lookup with caching
static void* findShadowAddressSafe(void* addr) {
    static struct {
        uint64_t code_addr;
        void* shadow_addr;
    } cache = {0, nullptr};

    uint64_t code_addr = (uint64_t)addr;

    // Check cache first
    if (cache.code_addr == code_addr) {
        return cache.shadow_addr;
    }

    int num_mappings = g_num_mappings.load(std::memory_order_acquire);

    for (int i = 0; i < num_mappings; i++) {
        const ShadowMapping& mapping = g_shadow_mappings[i];

        if (mapping.valid &&
            code_addr >= mapping.module_base &&
            code_addr < mapping.module_end) {
            uint64_t offset = code_addr - mapping.module_base;
            void* shadow_addr = (void*)(mapping.shadow_base + offset);

            // Update cache
            cache.code_addr = code_addr;
            cache.shadow_addr = shadow_addr;

            return shadow_addr;
        }
    }

    return nullptr;
}

// Minimal coverage update
static void updateCoverageSafe(uint64_t pc) {
    uint64_t cur_loc = ((pc >> 4) ^ (pc << 8)) & (MAP_SIZE - 1);
    uint16_t prev_loc = g_previous_loc.load(std::memory_order_relaxed);
    uint16_t map_idx = cur_loc ^ prev_loc;

    if (LibFuzzCounters) {
        __sync_fetch_and_add(&LibFuzzCounters[map_idx], 1);
    }

    g_previous_loc.store(cur_loc >> 1, std::memory_order_relaxed);
}

// Simplified coverage handler
static void coverageHandler(int /* signum */, siginfo_t* info, void* context) {
    if (!g_coverage_enabled.load(std::memory_order_acquire)) {
        return;
    }

    ucontext_t* uc = (ucontext_t*)context;
    void* fault_addr = info->si_addr;

    // Find shadow address
    void* shadow_addr = findShadowAddressSafe(fault_addr);
    if (!shadow_addr) {
        // Skip instruction
        __darwin_arm_thread_state64_set_pc(uc->uc_mcontext->__ss,
            __darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss) + 4);
        return;
    }

    // Update coverage
    updateCoverageSafe((uint64_t)fault_addr);

    // Make page writable
    if (mprotect((void*)pageAlign(fault_addr), vm_page_size,
                 PROT_READ | PROT_WRITE) != 0) {
        // Skip on failure
        __darwin_arm_thread_state64_set_pc(uc->uc_mcontext->__ss,
            __darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss) + 4);
        return;
    }

    // Read and restore original instruction
    uint32_t original_instruction;
    memcpy(&original_instruction, shadow_addr, sizeof(uint32_t));

    if (original_instruction == 0) {
        original_instruction = 0xd503201f; // ARM64 NOP
    }

    memcpy(fault_addr, &original_instruction, sizeof(uint32_t));

    // Flush instruction cache
    sys_icache_invalidate(fault_addr, sizeof(uint32_t));
    __asm__ volatile("dmb ishst" ::: "memory");

    // Restore protection
    mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_EXEC);
}

// Public interface
void updateCoverage(uint64_t curLoc) {
    updateCoverageSafe(curLoc);
}

extern "C" void installHandlers() {
    // Initialize shadow pool on first call
    static bool pool_initialized = false;
    if (!pool_initialized) {
        if (!initializeShadowPool()) {
            dlogn("Failed to initialize shadow memory pool");
            return;
        }
        pool_initialized = true;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_sigaction = coverageHandler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, nullptr) != 0) {
        dlogn("Failed to install SIGTRAP handler");
        return;
    }

    g_coverage_enabled.store(true, std::memory_order_release);
    dlogn("Coverage handlers installed");
}

extern "C" void libFuzzerCleanUp() {
    g_coverage_enabled.store(false, std::memory_order_release);
    signal(SIGTRAP, SIG_DFL);

    // Unmap shadow pool
    if (g_shadow_pool.base) {
        munmap(g_shadow_pool.base, g_shadow_pool.size);
        g_shadow_pool.base = nullptr;
    }

    dlogn("Coverage handlers cleaned up");
}
