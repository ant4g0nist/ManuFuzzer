//
//  instrumenter.mm
//  ManuFuzzer
//

#include <sys/types.h>
#include <sys/mman.h>
#include <mach/vm_statistics.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>

#include "coverage.h"
#include "utilities.h"
#include "disassembler.h"
#include "dyld_cache_parser.h"

#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>
#include <mach-o/getsect.h>
#include <mach/machine.h>
#include <mach-o/loader.h>
#import <mach/vm_page_size.h>
#include <mach-o/dyld_images.h>
#include <Foundation/Foundation.h>
#include <vector>

extern "C" void registerShadowMapping(uint64_t moduleBase, uint64_t shadowBase, size_t size);
#include <string>
#include <utility>
#include <errno.h>
#include <unordered_set>
#include <map>

task_t task;
// Global list to keep track of mmap'd regions for cleanup
static std::vector<std::pair<void*, size_t>> g_shadow_regions_to_unmap;
// Global set to track base addresses of modules with shadow memory
static std::unordered_set<uint32_t*> g_modules_with_shadow_memory;
// Global map to track all shadow memory allocations
static std::map<uint64_t, size_t> g_shadow_memory_map;
// Counter for unique shadow memory regions
static uint64_t g_shadow_region_counter = 0;
extern uint8_t *LibFuzzCounters;

// Shadow memory pool for memory efficiency
static struct {
    void* base;
    size_t size;
    size_t used;
    pthread_mutex_t mutex;
} g_shadow_pool = {nullptr, 0, 0, PTHREAD_MUTEX_INITIALIZER};

// Initialize shadow memory pool
static bool initializeShadowPool() {
    // Pre-allocate a large shadow memory pool (256MB)
    const size_t POOL_SIZE = 256 * 1024 * 1024;

    g_shadow_pool.base = mmap(nullptr, POOL_SIZE,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (g_shadow_pool.base == MAP_FAILED) {
        dlogn("Failed to allocate shadow memory pool: %s", strerror(errno));
        return false;
    }

    g_shadow_pool.size = POOL_SIZE;
    g_shadow_pool.used = 0;
    return true;
}

// Allocate from shadow pool
static void* allocateFromShadowPool(size_t size) {
    // Align size to page boundary
    size = (size + vm_page_size - 1) & ~(vm_page_size - 1);

    pthread_mutex_lock(&g_shadow_pool.mutex);

    if (!g_shadow_pool.base) {
        if (!initializeShadowPool()) {
            pthread_mutex_unlock(&g_shadow_pool.mutex);
            return nullptr;
        }
    }

    if (g_shadow_pool.used + size > g_shadow_pool.size) {
        pthread_mutex_unlock(&g_shadow_pool.mutex);
        return nullptr; // Pool exhausted
    }

    void* result = (char*)g_shadow_pool.base + g_shadow_pool.used;
    g_shadow_pool.used += size;

    pthread_mutex_unlock(&g_shadow_pool.mutex);
    return result;
}

// cleanup logic
static void actualManuFuzzerCleanup() {
    dlogn("Cleaning up %zu shadow memory regions", g_shadow_regions_to_unmap.size());

    for (const auto& region : g_shadow_regions_to_unmap) {
        if (munmap(region.first, region.second) == -1) {
            dlogn("Warning: Failed to munmap shadow region at %p (size %zu): %s",
                    region.first, region.second, strerror(errno));
        }
    }
    g_shadow_regions_to_unmap.clear();

    // Cleanup shadow pool
    pthread_mutex_lock(&g_shadow_pool.mutex);
    if (g_shadow_pool.base) {
        munmap(g_shadow_pool.base, g_shadow_pool.size);
        g_shadow_pool.base = nullptr;
        g_shadow_pool.size = 0;
        g_shadow_pool.used = 0;
    }
    pthread_mutex_unlock(&g_shadow_pool.mutex);

    dlogn("Shadow memory cleanup complete");
}

struct LibraryInfo {
    void* loadAddress;
    const char* path;
};

// These helper functions need to be outside extern "C" since they return C++ types
std::vector<LibraryInfo> findLibraryLoadAddresses(const char* libraryFilePath)
{
    std::vector<LibraryInfo> result;
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;

    kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &dyld_info_count);
    if (kr != KERN_SUCCESS)
        fatal("failed to get task info");

    const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*) task_dyld_info.all_image_info_addr;
    const struct dyld_image_info* image_infos = all_image_infos->infoArray;

    dlogn("infoArrayCount: %x\n", all_image_infos->infoArrayCount);

    // Find the specified library
    for(size_t i = 0; i < all_image_infos->infoArrayCount; i++)
    {
        const char* imageFilePath = image_infos[i].imageFilePath;
        mach_vm_address_t imageLoadAddress = (mach_vm_address_t)image_infos[i].imageLoadAddress;
        if (strstr(imageFilePath, libraryFilePath))
        {
            LibraryInfo targetLib = {(void*)imageLoadAddress, imageFilePath};
            result.push_back(targetLib);
            break;
        }
    }

    if (result.empty()) {
        dlogn("Warning: Failed to find load address of %s", libraryFilePath);
    }

    return result;
}

// Helper function to find a free shadow memory region
void* findFreeShadowRegion(size_t size) {
    // Base shadow memory address - use a high memory region
    const uint64_t SHADOW_BASE = 0x300000000000ULL;
    const uint64_t SHADOW_REGION_SIZE = 0x100000000ULL; // 4GB per region

    // Try to find a free region
    for (uint64_t region = 0; region < 100; region++) {
        uint64_t region_start = SHADOW_BASE + (region * SHADOW_REGION_SIZE);

        // Check if this region overlaps with any existing allocation
        bool conflict = false;
        for (const auto& entry : g_shadow_memory_map) {
            uint64_t existing_start = entry.first;
            uint64_t existing_end = existing_start + entry.second;
            uint64_t new_end = region_start + size;

            if ((region_start >= existing_start && region_start < existing_end) ||
                (new_end > existing_start && new_end <= existing_end) ||
                (region_start <= existing_start && new_end >= existing_end)) {
                conflict = true;
                break;
            }
        }

        if (!conflict) {
            return (void*)region_start;
        }
    }

    // If we couldn't find a free region, fall back to a unique address
    return (void*)(SHADOW_BASE + (g_shadow_region_counter++ * 0x10000000ULL));
}

// Check available memory
static bool checkAvailableMemory(size_t requiredMB) {
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t host_size = sizeof(vm_stat) / sizeof(natural_t);

    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                         (host_info64_t)&vm_stat, &host_size) == KERN_SUCCESS) {
        uint64_t free_memory = vm_stat.free_count * vm_page_size;
        uint64_t inactive_memory = vm_stat.inactive_count * vm_page_size;
        uint64_t available_memory = free_memory + inactive_memory;

        uint64_t required_bytes = requiredMB * 1024 * 1024;

        dlogn("Available memory: %llu MB (need %zu MB)",
              available_memory / (1024*1024), requiredMB);

        return available_memory >= required_bytes;
    }

    return true; // Assume there's enough if we can't check
}

extern "C" {

void* findLibraryLoadAddress(const char* libraryFilePath)
{
    auto libraries = findLibraryLoadAddresses(libraryFilePath);
    if (libraries.empty()) {
        return NULL;
    }
    return libraries[0].loadAddress;
}

void getMachHeader(void *mach_header_address, struct mach_header_64 *mach_header)
{
    struct mach_header_64* header = (struct mach_header_64*) mach_header_address;
    dlogn("mach_header->magic %x", header->magic);
    *mach_header = *header;
}

void getLoadCommandsBuffer(void *mach_header_address, const struct mach_header_64 * /* unused */, void **load_commands)
{
    *load_commands = (void*)((uint64_t)mach_header_address + sizeof(struct mach_header_64));
}

struct section_64 *getSection(void * section_address, const int /* index */, const int swapBytes)
{
    struct section_64 *section = (struct section_64 *) malloc(sizeof(struct section_64));
    memcpy(section, section_address, sizeof(struct section_64));

    if (swapBytes) {
        // swap_section_64 is deprecated, manually swap the fields
        // For simplicity, we'll skip byte swapping since most macOS binaries are native endian
        dlogn("WARNING: Byte swapping requested but not implemented for sections");
    }

    return section;
}

void parseAndInstrument(const char *module_name, uint32_t* baseAddress)
{
    // Check if this module has already been processed
    if (g_modules_with_shadow_memory.count(baseAddress)) {
        dlogn("Shadow memory for module %s (base %p) already processed. Skipping.", module_name, baseAddress);
        return;
    }

    struct mach_header_64 mach_header;
    getMachHeader(baseAddress, &mach_header);

    boolean_t swapBytes = false;
    if (mach_header.magic == MH_CIGAM || mach_header.magic == MH_CIGAM_64 || mach_header.magic == FAT_CIGAM)
        swapBytes = true;

    void *load_commands_buffer = NULL;
    getLoadCommandsBuffer(baseAddress, &mach_header, &load_commands_buffer);

    uint64_t offset = 0;
    bool shadow_memory_allocated_for_this_module = false;

    // Find the base VM address of the first segment to calculate slide
    uint64_t image_base_vmaddr = 0;
    {
        uint64_t search_offset = 0;
        for (unsigned int search_i = 0; search_i < mach_header.ncmds; ++search_i) {
            struct load_command *search_cmd = (struct load_command *)((uint64_t)load_commands_buffer + search_offset);
            if (search_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *first_seg = (struct segment_command_64*)search_cmd;
                image_base_vmaddr = first_seg->vmaddr;
                break;
            }
            search_offset += search_cmd->cmdsize;
        }
    }

    for (unsigned int i = 0; i < mach_header.ncmds; ++i)
    {
        struct load_command *load_cmd = (struct load_command *)((uint64_t)load_commands_buffer + offset);
        struct segment_command_64 *segment_cmd = (struct segment_command_64*) load_cmd;

        if (load_cmd->cmd == LC_SEGMENT_64 && strcmp(segment_cmd->segname, "__TEXT") == 0)
        {
            dlogn("Processing __TEXT segment for module %s (base %p)", module_name, baseAddress);
            dlogn("base address: %p", baseAddress);

            // Calculate the slide (ASLR offset)
            uint64_t slide = (uint64_t)baseAddress - image_base_vmaddr;

            // Calculate the actual runtime address of the segment
            uint64_t addr = segment_cmd->vmaddr + slide;

            uint32_t segSize = pageAlignEnd(segment_cmd->vmsize);

            // Skip if memory is low
            if (segSize > 50 * 1024 * 1024 && !checkAvailableMemory(segSize / (1024 * 1024) * 2)) {
                dlogn("Skipping large segment (low memory): %s (size=%u MB)",
                    segment_cmd->segname, segSize / (1024 * 1024));
                offset += load_cmd->cmdsize;
                continue;
            }

            dlogn("Segment %s: vmaddr=0x%llx, slide=0x%llx, runtime_addr=0x%llx, size=0x%x",
                  segment_cmd->segname, segment_cmd->vmaddr, slide, addr, segSize);

            // Make segment writable to insert breakpoints
            kern_return_t kr = vm_protect((vm_map_t)task, (vm_address_t)addr, (vm_size_t)segSize,
                                        false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

            if (kr != KERN_SUCCESS) {
                dlogn("ERROR: vm_protect failed for addr: 0x%llx, size: 0x%x, kr: %d", addr, segSize, kr);
                fatal("Failed to make segment addr: %llx as writable (error: %d)", addr, kr);
            }

            // Try to allocate from shadow pool first
            void* shadowAddr = allocateFromShadowPool(segSize);

            if (!shadowAddr) {
                // Fallback to finding a free region
                dlogn("Shadow pool allocate failed, using regular mmap");
                shadowAddr = findFreeShadowRegion(segSize);
                shadowAddr = mmap(shadowAddr, segSize, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

                if (shadowAddr == MAP_FAILED) {
                    dlogn("ERROR: Failed to allocate shadow memory for %s: %s",
                          module_name, strerror(errno));

                    // Clean up and restore protection
                    vm_protect((vm_map_t)task, (vm_address_t)addr, (vm_size_t)segSize,
                              false, VM_PROT_READ | VM_PROT_EXECUTE);
                    offset += load_cmd->cmdsize;
                    continue;
                }

                // Register for cleanup
                g_shadow_regions_to_unmap.push_back({shadowAddr, segSize});
            }

            dlogn("Shadow allocation: module=%s, addr=%p, shadow=%p, size=%u",
                  module_name, (void*)addr, shadowAddr, segSize);

            // Track this shadow allocation
            g_shadow_memory_map[(uint64_t)shadowAddr] = segSize;
            shadow_memory_allocated_for_this_module = true;

            // Register with coverage handler
            registerShadowMapping(addr, (uint64_t)shadowAddr, segSize);

            // Process sections
            uint64_t sections_offset = 0;
            void* sections_base = (void*)((uint64_t)segment_cmd + sizeof(struct segment_command_64));

            for (unsigned int isect = 0; isect < segment_cmd->nsects; isect++)
            {
                uint64_t sect_address = (uint64_t)sections_base + sections_offset;
                struct section_64 * sect = getSection((void*)(sect_address), isect, swapBytes);

                if (sect->flags & S_ATTR_SOME_INSTRUCTIONS || sect->flags & S_ATTR_PURE_INSTRUCTIONS)
                {
                    // Skip large sections if memory is low
                    if (sect->size > 20 * 1024 * 1024 && !checkAvailableMemory(20)) {
                        dlogn("Skipping large section (low memory): %s (size=%llu MB)",
                             sect->sectname, sect->size / (1024 * 1024));
                        free(sect);
                        sections_offset += sizeof(struct section_64);
                        continue;
                    }

                    size_t size;
                    uint8_t *data = (uint8_t *) getsectiondata((const struct mach_header_64 *)baseAddress,
                                                              "__TEXT", sect->sectname, &size);

                    if (data) {
                        uint64_t sect_offset = sect->addr - segment_cmd->vmaddr;
                        uint8_t *runtime_section_addr = (uint8_t*)addr + sect_offset;

                        dlogn("Instrumenting section %s: runtime addr=%p, size=%zu",
                              sect->sectname, runtime_section_addr, size);

                        instrumentASectionWithMapping(baseAddress, addr, (uint64_t)shadowAddr,
                                                    runtime_section_addr, size);
                    } else {
                        dlogn("Warning: getsectiondata returned NULL for module %s, section %s",
                              module_name, sect->sectname);
                    }
                }

                free(sect);
                sections_offset += sizeof(struct section_64);
            }

            // Restore segment protection
            kr = vm_protect((vm_map_t)task, (vm_address_t)addr, (vm_size_t)segSize,
                          false, VM_PROT_READ | VM_PROT_EXECUTE);

            if (kr != KERN_SUCCESS)
                fatal("failed to make segment addr: %llx as executable", addr);
        }

        offset += load_cmd->cmdsize;
    }

    // Mark this module as having shadow memory allocated
    if (shadow_memory_allocated_for_this_module) {
        g_modules_with_shadow_memory.insert(baseAddress);
        dlogn("Registered module %s (base %p) as having shadow memory.", module_name, baseAddress);
    }
}

int instrumentMe(const char * libraryFilePath)
{
    llvmInitialize();

    // Check available memory before starting
    if (!checkAvailableMemory(500)) {
        dlogn("WARNING: Low memory available. Instrumentation may be limited.");
    }

    if (!task)
    {
        kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &task);
        if (kr != KERN_SUCCESS)
            fatal("failed to get task_for_pid");
    }

    std::vector<LibraryInfo> libraries = findLibraryLoadAddresses(libraryFilePath);
    if (libraries.empty()) {
        dlogn("Library %s not found. Skipping.", libraryFilePath);
        return -1;
    }

    // Extract just the filename from libraryFilePath for dyld cache lookup
    const char* baseFileName = strrchr(libraryFilePath, '/');
    if (baseFileName == NULL) {
        baseFileName = libraryFilePath;
    } else {
        baseFileName++; // Skip the '/'
    }

    // If this is a library in dyld cache, we need to instrument other libraries that share pages
    std::vector<std::string> moduleGroup = getModuleGroup(baseFileName);
    if (!moduleGroup.empty()) {
        dlogn("Library %s is in dyld cache with %zu related modules",
              baseFileName, moduleGroup.size() - 1);

        task_dyld_info_data_t task_dyld_info;
        mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
        kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO,
                                    (task_info_t)&task_dyld_info, &dyld_info_count);

        if (kr == KERN_SUCCESS) {
            const struct dyld_all_image_infos* all_image_infos =
                (const struct dyld_all_image_infos*) task_dyld_info.all_image_info_addr;
            const struct dyld_image_info* image_infos = all_image_infos->infoArray;

            // For each library in the module group, find its load address and instrument it
            for (const auto& moduleName : moduleGroup) {
                for (size_t i = 0; i < all_image_infos->infoArrayCount; i++) {
                    const char* imageFilePath = image_infos[i].imageFilePath;
                    const char* imageFileName = strrchr(imageFilePath, '/');
                    if (imageFileName != NULL) {
                        imageFileName++; // Skip the '/'
                        if (moduleName == imageFileName) {
                            void* loadAddr = (void*)image_infos[i].imageLoadAddress;
                            dlogn("Instrumenting related module %s at %p", imageFileName, loadAddr);
                            parseAndInstrument(imageFileName, (uint32_t*)loadAddr);
                        }
                    }
                }
            }
        }
    } else {
        // If not in dyld cache or we couldn't determine, just instrument the one library
        void* loadAddr = libraries[0].loadAddress;
        parseAndInstrument(libraryFilePath, (uint32_t*)loadAddr);
    }

    dlogn("instrumentMe %s done", libraryFilePath);
    return 0;
}

// Function to be called by atexit for cleaning up shadow memory regions
void manuFuzzerAtExitCleanup() {
    actualManuFuzzerCleanup();
}

} // Close extern "C" block
