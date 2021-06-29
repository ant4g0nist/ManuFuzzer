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
extern task_t task;
bool llvmInitialized = false;

void llvmInitialize()
{
	if (llvmInitialized)
	{
		dlogn("llvm Initialized");
		return;
	}

	dlogn("llvm Initialize");
	LLVMInitializeAArch64Disassembler();
	LLVMInitializeAArch64TargetInfo();
	LLVMInitializeAArch64TargetMC();
	dlogn("llvm Initialized");

	llvmInitialized = true;
}

int instrumentASection(uint32_t* baseAddress, uint64_t shadow, uint8_t *section_data, size_t section_size)
{
	LLVMDisasmContextRef dcr = LLVMCreateDisasm(
			"arm64-darwin-unknown", // TripleName
			NULL,
			0,
			NULL,
			NULL
		);

	if (dcr == NULL)
	{
		fatal("Could not create disassembler");
	}
	
	char Inst[1024];
	size_t pos = 0 ;
	
	while (pos < section_size)
	{
		uint32_t * PC 		= (uint32_t *)(section_data + pos);
		struct LLVMDisasmInstructionRes res = LLVMDisasmInstruction(dcr, (uint8_t*)PC, section_size - pos, (uint64_t) PC, Inst, sizeof(Inst));

		if (res.isBranch)
		{
			uint32_t *shadowAddr 	= (uint32_t *)shadowMeUp(PC);
			uint32_t origByte 		= *PC;
			*shadowAddr 			= origByte;

			uint32_t brk_instr = 0xd4200000 | (1 << 5);

			*PC = brk_instr;
			
			dlogn("branch: true addr: %llx origByte: %x shadow: %llx", (uint64_t)PC, origByte, (uint64_t)shadowAddr);
		}

		pos += 4;
	}

	LLVMDisasmDispose(dcr);
	dlogn("done");
	return 1;
}