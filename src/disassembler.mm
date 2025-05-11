//
//  disassembler.mm
//  ManuFuzzer
//
//  Created by ant4g0nist
//
// Implementation of disassembler functions, using LLVM

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <unordered_set>
#include <vector>
#include <string.h>

#include "utilities.h"
#include "disassembler.h"

// Include LLVM headers only if explicitly available
#if defined(LLVM_AVAILABLE)
  #include <llvm-c/Target.h>
  #include <llvm-c/Disassembler.h>
  #include <llvm-c/DisassemblerTypes.h>
#endif

extern task_t task;
bool llvmInitialized = false;

// Track already instrumented addresses to avoid duplicate instrumentation
std::unordered_set<uint64_t> instrumentedAddresses;

extern "C" {

void llvmInitialize()
{
    if (llvmInitialized)
    {
        dlogn("disassembler already initialized");
        return;
    }

    dlogn("initializing disassembler");

#if defined(LLVM_AVAILABLE)
    // Initialize LLVM disassembler for AArch64
    LLVMInitializeAArch64Disassembler();
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64TargetMC();
    dlogn("LLVM disassembler initialized");
#else
    // If LLVM is not available, indicate a fatal error as we removed the fallback
    fatal("LLVM is required for this build but not available.");
#endif

    llvmInitialized = true;
    instrumentedAddresses.clear();
}

/**
 * Instruments a code section by inserting breakpoints at branch instructions
 *
 * @param baseAddress The base address of the module
 * @param shadow The shadow memory address
 * @param section_data Pointer to the section data to instrument
 * @param section_size Size of the section data
 * @return 1 if successful, 0 otherwise
 */
int instrumentASection(uint32_t* /* baseAddress */, uint64_t /* shadow */, uint8_t *section_data, size_t section_size)
{
#if defined(LLVM_AVAILABLE)
    LLVMDisasmContextRef dcr = LLVMCreateDisasm(
        "arm64-darwin-unknown",
        NULL,
        0,
        NULL,
        NULL
    );

    if (dcr == NULL) {
        fatal("Could not create LLVM disassembler");
        return 0;
    }

    char Inst[1024];
    size_t pos = 0;
    int instrumentedCount = 0;

    while (pos < section_size) {
        uint32_t *PC = (uint32_t *)(section_data + pos);
        uint64_t pc_addr = (uint64_t)PC;

        // Skip if already instrumented
        if (instrumentedAddresses.find(pc_addr) != instrumentedAddresses.end()) {
            pos += 4;
            continue;
        }

        struct LLVMDisasmInstructionRes result = LLVMDisasmInstruction(
            dcr,
            (uint8_t*)PC,
            section_size - pos,
            pc_addr,
            Inst,
            sizeof(Inst)
        );

        size_t instSize = result.OutStringSize;
        bool isBranch = result.isBranch;

        if (instSize > 0 && isBranch) {
            uint32_t *shadowAddr = (uint32_t *)shadowMeUp(PC);
            uint32_t origByte = *PC;
            *shadowAddr = origByte;

            // Use standard ARM64 breakpoint instruction
            uint32_t brk_instr = 0xd4200000 | (1 << 5);

            *PC = brk_instr;

            dlogn("Instrumented branch at %llx, orig: %x, shadow: %llx",
                pc_addr, origByte, (uint64_t)shadowAddr);

            instrumentedAddresses.insert(pc_addr);
            instrumentedCount++;
        }

        pos += 4;  // Move to next instruction
    }

    LLVMDisasmDispose(dcr);
    dlogn("Instrumented %d points in section", instrumentedCount);
    return 1;
#else
    // If LLVM is not available and we removed fallback, we must indicate an error.
    fatal("LLVM is required for instrumentation but not available.");
    return 0;
#endif
}

/**
 * Instruments a code section with explicit segment and shadow base mapping
 *
 * @param baseAddress The base address of the module
 * @param segmentBase The base address of the segment being instrumented
 * @param shadowBase The base address of the shadow memory
 * @param section_data Pointer to the section data to instrument
 * @param section_size Size of the section data
 * @return 1 if successful, 0 otherwise
 */
int instrumentASectionWithMapping(uint32_t* /* baseAddress */, uint64_t segmentBase, uint64_t shadowBase,
                                 uint8_t *section_data, size_t section_size)
{
#if defined(LLVM_AVAILABLE)
    LLVMDisasmContextRef dcr = LLVMCreateDisasm(
        "arm64-darwin-unknown",
        NULL,
        0,
        NULL,
        NULL
    );

    if (dcr == NULL) {
        fatal("Could not create LLVM disassembler");
        return 0;
    }

    char Inst[1024];
    size_t pos = 0;
    int instrumentedCount = 0;

    dlogn("instrumentASectionWithMapping: segmentBase=0x%llx, shadowBase=0x%llx, section_data=%p, size=%zu",
          segmentBase, shadowBase, section_data, section_size);

    while (pos < section_size) {
        uint32_t *PC = (uint32_t *)(section_data + pos);
        uint64_t pc_addr = (uint64_t)PC;

        // Skip if already instrumented
        if (instrumentedAddresses.find(pc_addr) != instrumentedAddresses.end()) {
            pos += 4;
            continue;
        }

        struct LLVMDisasmInstructionRes result = LLVMDisasmInstruction(
            dcr,
            (uint8_t*)PC,
            section_size - pos,
            pc_addr,
            Inst,
            sizeof(Inst)
        );

        size_t instSize = result.OutStringSize;
        bool isBranch = result.isBranch;

        if (instSize > 0 && isBranch) {
            // Calculate shadow address using the mapping provided
            // Shadow = (PC - segmentBase) + shadowBase
            uint64_t offset = (uint64_t)PC - segmentBase;
            uint32_t *shadowAddr = (uint32_t *)(shadowBase + offset);

            uint32_t origByte = *PC;

            // Write original instruction to shadow memory
            *shadowAddr = origByte;

            // Use standard ARM64 breakpoint instruction (SIGTRAP)
            uint32_t brk_instr = 0xd4200020; // BRK #0x1

            *PC = brk_instr;

            dlogn("Instrumented branch at %llx, orig: %x, shadow: %llx (offset: %llx)",
                pc_addr, origByte, (uint64_t)shadowAddr, offset);

            instrumentedAddresses.insert(pc_addr);
            instrumentedCount++;
        }

        pos += 4;  // Move to next instruction
    }

    LLVMDisasmDispose(dcr);
    dlogn("Instrumented %d points in section", instrumentedCount);
    return 1;
#else
    // If LLVM is not available and we removed fallback, we must indicate an error.
    fatal("LLVM is required for instrumentation but not available.");
    return 0;
#endif
}

} // extern "C"
