//
//  llvm_mc.h
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#ifndef ManuFuzzer_DISASSEMBLER_H
#define ManuFuzzer_DISASSEMBLER_H

void llvmInitialize();
int disassemble(uint8_t* bytes, int size);
int instrumentASection(uint32_t* baseAddress, uint64_t shadow, uint8_t *section_data, size_t section_size);

#endif