//
//  disassembler.mm
//  ManuFuzzer
//

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unordered_set>
#include <vector>
#include <string.h>
#include <mach/mach.h>

#include "utilities.h"
#include "disassembler.h"

#if defined(LLVM_AVAILABLE)
  #include <llvm-c/Target.h>
  #include <llvm-c/Disassembler.h>
  #include <llvm-c/DisassemblerTypes.h>
#endif

extern task_t task;
bool llvmInitialized = false;
std::unordered_set<uint64_t> instrumentedAddresses;

extern "C" {

void llvmInitialize() {
    if (llvmInitialized) {
        dlogn("disassembler already initialized");
        return;
    }

    dlogn("initializing disassembler");

#if defined(LLVM_AVAILABLE)
    LLVMInitializeAArch64Disassembler();
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64TargetMC();
    dlogn("LLVM disassembler initialized");
#else
    fatal("LLVM is required for this build but not available.");
#endif

    llvmInitialized = true;
    instrumentedAddresses.clear();
}

int instrumentASectionWithMapping(uint32_t* /* baseAddress */, uint64_t segmentBase, uint64_t shadowBase,
                                 uint8_t *section_data, size_t section_size) {
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

    // Validate shadow memory is accessible before starting
    if (mprotect((void*)shadowBase, section_size, PROT_READ | PROT_WRITE) != 0) {
        dlogn("ERROR: Shadow memory at 0x%llx is not accessible", shadowBase);
        LLVMDisasmDispose(dcr);
        return 0;
    }

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
            // Calculate shadow address using proper mapping
            uint64_t offset = pc_addr - segmentBase;

            // Validate offset is within bounds
            if (offset >= section_size) {
                dlogn("ERROR: Offset 0x%llx exceeds section size 0x%zx", offset, section_size);
                pos += 4;
                continue;
            }

            uint32_t *shadowAddr = (uint32_t *)(shadowBase + offset);
            uint32_t origByte = *PC;

            // Validate original instruction
            if (origByte == 0) {
                dlogn("WARNING: Original instruction at %p is zero, skipping", PC);
                pos += 4;
                continue;
            }

            // Write original instruction to shadow memory
            *shadowAddr = origByte;

            // Use standard ARM64 SIGTRAP breakpoint
            uint32_t brk_instr = 0xd4200020; // BRK #0x1

            // Replace instruction with breakpoint
            *PC = brk_instr;

            dlogn("Instrumented branch at %llx, orig: %x, shadow: %llx (offset: %llx)",
                pc_addr, origByte, (uint64_t)shadowAddr, offset);

            instrumentedAddresses.insert(pc_addr);
            instrumentedCount++;
        }

        pos += 4;  // Move to next instruction
    }

    LLVMDisasmDispose(dcr);
    dlogn("Instrumented %d branch points in section", instrumentedCount);

    // Return the instrumented count to satisfy the warning
    return (instrumentedCount > 0) ? 1 : 0;
#else
    fatal("LLVM is required for instrumentation but not available.");
    return 0;
#endif
}

} // extern "C"
