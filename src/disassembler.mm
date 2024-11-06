//
//  llvm_mc.mm
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#include "llvm-c/Target.h"
#include "llvm-c/Disassembler.h"
#include "llvm-c/DisassemblerTypes.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCInstrAnalysis.h"

#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>

#include "utilities.h"

using namespace llvm;

////////////////////////////////////////////////////////////////////////////////
// Global Variables & Constants
////////////////////////////////////////////////////////////////////////////////

extern task_t task;
static bool llvmInitialized = false;

// Constants for LLVM initialization
static constexpr const char* TARGET_TRIPLE = "arm64-darwin-unknown";
static constexpr uint32_t BREAK_INSTRUCTION = 0xd4200000 | (1 << 5);

////////////////////////////////////////////////////////////////////////////////
// LLVM Context Management
////////////////////////////////////////////////////////////////////////////////

class LLVMContextManager {
private:
    LLVMDisasmContextRef disasmCtx;
    
public:
    LLVMContextManager() : disasmCtx(nullptr) {}
    
    bool initialize() {
        disasmCtx = LLVMCreateDisasm(
            TARGET_TRIPLE,
            nullptr,  // void* DisInfo
            0,        // int TagType
            nullptr,  // LLVMOpInfoCallback GetOpInfo
            nullptr   // LLVMSymbolLookupCallback SymbolLookUp
        );
        
        return disasmCtx != nullptr;
    }
    
    LLVMDisasmContextRef getContext() const {
        return disasmCtx;
    }
    
    ~LLVMContextManager() {
        if (disasmCtx) {
            LLVMDisasmDispose(disasmCtx);
        }
    }
    
    // Prevent copying
    LLVMContextManager(const LLVMContextManager&) = delete;
    LLVMContextManager& operator=(const LLVMContextManager&) = delete;
};

////////////////////////////////////////////////////////////////////////////////
// Error Handling
////////////////////////////////////////////////////////////////////////////////

class ScopedErrorHandler {
private:
    const char* operation;
    
public:
    explicit ScopedErrorHandler(const char* op) : operation(op) {
        dlogn("Starting %s", operation);
    }
    
    ~ScopedErrorHandler() {
        dlogn("Completed %s", operation);
    }
    
    void reportError(const char* message) {
        fatal("Error in %s: %s", operation, message);
    }
};

////////////////////////////////////////////////////////////////////////////////
// Memory Management
////////////////////////////////////////////////////////////////////////////////

class ShadowMemoryManager {
public:
    static bool updateInstruction(uint32_t* target, uint32_t* shadow, uint32_t newInstr) {
        *shadow = *target;
        *target = newInstr;
        return true;
    }
    
    static bool validateAddress(const void* addr, size_t size) {
        if (!addr) {
            return false;
        }
        
        // Check if the address range is valid
        return ((uintptr_t)addr + size) > (uintptr_t)addr;
    }
};

////////////////////////////////////////////////////////////////////////////////
// LLVM Initialization
////////////////////////////////////////////////////////////////////////////////

void llvmInitialize() {
    ScopedErrorHandler errorHandler("LLVM Initialization");
    
    if (llvmInitialized) {
        dlogn("LLVM already initialized");
        return;
    }
    
    LLVMInitializeAArch64Disassembler();
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64TargetMC();
    
    llvmInitialized = true;
    dlogn("LLVM initialization complete");
}

////////////////////////////////////////////////////////////////////////////////
// Instruction Analysis
////////////////////////////////////////////////////////////////////////////////

class InstructionAnalyzer {
private:
    LLVMContextManager& ctxManager;
    
public:
    explicit InstructionAnalyzer(LLVMContextManager& manager) : ctxManager(manager) {}
    
    bool analyzeBranch(const uint8_t* instruction, size_t remainingSize, uint64_t pc) {
        char instStr[256];
        // Cast away constness just for the API call
        uint8_t* nonConstInstr = const_cast<uint8_t*>(instruction);
        auto result = LLVMDisasmInstruction(
            ctxManager.getContext(),
            nonConstInstr,
            remainingSize,
            pc,
            instStr,
            sizeof(instStr)
        );
        
        return result.isBranch;
    }
};

////////////////////////////////////////////////////////////////////////////////
// Section Instrumentation
////////////////////////////////////////////////////////////////////////////////

class SectionInstrumenter {
private:
    LLVMContextManager contextManager;
    InstructionAnalyzer* analyzer;
    
    bool instrumentInstruction(uint32_t* pc, uint32_t* shadow) {
        if (!ShadowMemoryManager::validateAddress(pc, sizeof(uint32_t)) ||
            !ShadowMemoryManager::validateAddress(shadow, sizeof(uint32_t))) {
            return false;
        }
        
        return ShadowMemoryManager::updateInstruction(pc, shadow, BREAK_INSTRUCTION);
    }
    
public:
    SectionInstrumenter() : analyzer(nullptr) {
        if (!contextManager.initialize()) {
            fatal("Failed to initialize LLVM disassembly context");
        }
        analyzer = new InstructionAnalyzer(contextManager);
    }
    
    ~SectionInstrumenter() {
        delete analyzer;
    }
    
    bool instrumentSection(uint32_t* baseAddress, uint64_t shadow, uint8_t* sectionData, size_t sectionSize) {
        ScopedErrorHandler errorHandler("Section Instrumentation");
        
        if (!ShadowMemoryManager::validateAddress(sectionData, sectionSize)) {
            errorHandler.reportError("Invalid section data or size");
            return false;
        }
        
        size_t pos = 0;
        while (pos < sectionSize) {
            uint32_t* pc = (uint32_t*)(sectionData + pos);
            
            if (analyzer->analyzeBranch((uint8_t*)pc, sectionSize - pos, (uint64_t)pc)) {
                uint32_t* shadowAddr = (uint32_t*)shadowMeUp(pc);
                
                dlogn("Branch found: addr: %llx shadow: %llx", (uint64_t)pc, (uint64_t)shadowAddr);
                
                if (!instrumentInstruction(pc, shadowAddr)) {
                    errorHandler.reportError("Failed to instrument instruction");
                    return false;
                }
            }
            
            pos += sizeof(uint32_t);
        }
        
        return true;
    }
};

////////////////////////////////////////////////////////////////////////////////
// Public Interface
////////////////////////////////////////////////////////////////////////////////

int instrumentASection(uint32_t* baseAddress, uint64_t shadow, uint8_t* sectionData, size_t sectionSize) {
    ScopedErrorHandler errorHandler("Section Analysis");
    
    if (!llvmInitialized) {
        errorHandler.reportError("LLVM not initialized");
        return -1;
    }
    
    SectionInstrumenter instrumenter;
    if (!instrumenter.instrumentSection(baseAddress, shadow, sectionData, sectionSize)) {
        return -1;
    }
    
    return 0;
}