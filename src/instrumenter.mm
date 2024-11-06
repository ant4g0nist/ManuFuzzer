//
//  instrumenter.mm
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#include "coverage.h"
#include "utilities.h"
#include "disassembler.h"

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

task_t task;
extern uint8_t *LibFuzzCounters;

// Structure to hold Mach-O parsing context
typedef struct {
    void* baseAddress;
    struct mach_header_64* header;
    void* loadCommandsBuffer;
    boolean_t swapBytes;
} MachOContext;

// Structure to hold segment processing context
typedef struct {
    vm_address_t address;
    vm_size_t size;
    uint32_t slide;
    void* shadowAddr;
} SegmentContext;

////////////////////////////////////////////////////////////////////////////////
// Error handling utilities
////////////////////////////////////////////////////////////////////////////////

static kern_return_t setSegmentProtection(vm_address_t addr, vm_size_t size, vm_prot_t protection) {
    kern_return_t kr = vm_protect((vm_map_t)task, addr, size, false, protection);
    if (kr != KERN_SUCCESS) {
        fatal("Failed to set segment protection at addr: %llx, protection: %d", addr, protection);
    }
    return kr;
}

////////////////////////////////////////////////////////////////////////////////
// Mach-O parsing utilities
////////////////////////////////////////////////////////////////////////////////

static void* findLibraryLoadAddress(const char* libraryFilePath) {
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;

    kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &dyld_info_count);
    if (kr != KERN_SUCCESS) {
        fatal("Failed to get task info");
    }

    const struct dyld_all_image_infos* all_image_infos = 
        (const struct dyld_all_image_infos*)task_dyld_info.all_image_info_addr;
    const struct dyld_image_info* image_infos = all_image_infos->infoArray;

    dlogn("infoArrayCount: %x", all_image_infos->infoArrayCount);

    for (size_t i = 0; i < all_image_infos->infoArrayCount; i++) {
        if (strstr(image_infos[i].imageFilePath, libraryFilePath)) {
            return (void*)image_infos[i].imageLoadAddress;
        }
    }

    fatal("Failed to find load address of %s", libraryFilePath);
    return NULL;
}

static void initializeMachOContext(void* address, MachOContext* ctx) {
    ctx->baseAddress = address;
    ctx->header = (struct mach_header_64*)address;
    ctx->swapBytes = (ctx->header->magic == MH_CIGAM || 
                     ctx->header->magic == MH_CIGAM_64 || 
                     ctx->header->magic == FAT_CIGAM);
    ctx->loadCommandsBuffer = (void*)((uint64_t)address + sizeof(struct mach_header_64));
}

static struct section_64* getSection(void* section_address, int index, boolean_t swapBytes) {
    struct section_64* section = (struct section_64*)malloc(sizeof(struct section_64));
    if (!section) {
        fatal("Failed to allocate memory for section");
    }

    memcpy(section, section_address, sizeof(struct section_64));
    
    if (swapBytes) {
        swap_section_64(section, 1, NX_UnknownByteOrder);
    }

    return section;
}

////////////////////////////////////////////////////////////////////////////////
// Segment processing
////////////////////////////////////////////////////////////////////////////////

static void* setupShadowMemory(void* lib_page_start, vm_size_t size) {
    if ((uintptr_t)lib_page_start % vm_page_size != 0) {
        lib_page_start = (void*)pageAlign(lib_page_start);
    }

    void* shadowAddr = shadowMeUp(lib_page_start);
    dlogn("Shadow starts at: %llx", (uint64_t)shadowAddr);

    void* shadow = mmap(shadowAddr, size + vm_page_size, 
                       PROT_READ | PROT_WRITE, 
                       MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);

    if (shadow == MAP_FAILED) {
        fatal("Failed to mmap shadow memory: %s", strerror(errno));
    }

    return shadow;
}

static void processTextSegment(struct segment_command_64* segment_cmd, MachOContext* ctx) {
    SegmentContext segCtx = {
        .address = (vm_address_t)((uint64_t)ctx->baseAddress),
        .size = pageAlignEnd(segment_cmd->vmsize),
        .slide = (uint32_t)((uint64_t)ctx->baseAddress - segment_cmd->vmaddr)
    };

    // Make segment writable for instrumentation
    setSegmentProtection(segCtx.address, segCtx.size, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    // Setup shadow memory
    segCtx.shadowAddr = setupShadowMemory((void*)segCtx.address, segCtx.size);

    // Process sections
    void* sections_base = (void*)((uint64_t)segment_cmd + sizeof(struct segment_command_64));
    uint64_t sections_offset = 0;

    for (int isect = 0; isect < segment_cmd->nsects; isect++) {
        void* sect_address = (void*)((uint64_t)sections_base + sections_offset);
        struct section_64* sect = getSection(sect_address, isect, ctx->swapBytes);

        if (sect->flags & (S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS)) {
            size_t size;
            uint8_t* data = (uint8_t*)getsectiondata(
                (const struct mach_header_64*)ctx->baseAddress,
                "__TEXT",
                sect->sectname,
                &size
            );

            instrumentASection((uint32_t*)ctx->baseAddress, 
                             (uint64_t)segCtx.shadowAddr, 
                             data, 
                             size);
        }

        free(sect);
        sections_offset += sizeof(struct section_64);
    }

    // Restore segment protection
    setSegmentProtection(segCtx.address, segCtx.size, VM_PROT_READ | VM_PROT_EXECUTE);
}

static void processLoadCommands(MachOContext* ctx) {
    uint64_t offset = 0;
    struct mach_header_64* header = ctx->header;

    for (int i = 0; i < header->ncmds; ++i) {
        struct load_command* load_cmd = 
            (struct load_command*)((uint64_t)ctx->loadCommandsBuffer + offset);
        
        if (load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment_cmd = (struct segment_command_64*)load_cmd;
            
            if (strcmp(segment_cmd->segname, "__TEXT") == 0) {
                processTextSegment(segment_cmd, ctx);
            }
        }
        
        offset += load_cmd->cmdsize;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Main instrumentation interface
////////////////////////////////////////////////////////////////////////////////

extern "C" int instrumentMe(const char* libraryFilePath) {
    llvmInitialize();
    
    void* loadAddr = findLibraryLoadAddress(libraryFilePath);
    if (!loadAddr) {
        return -1;
    }

    if (!task) {
        kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &task);
        if (kr != KERN_SUCCESS) {
            fatal("Failed to get task_for_pid");
        }
    }

    MachOContext ctx;
    initializeMachOContext(loadAddr, &ctx);
    processLoadCommands(&ctx);

    dlogn("instrumentMe %s done", libraryFilePath);
    return 0;
}