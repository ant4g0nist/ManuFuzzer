//
//  disassembler.h
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#ifndef disassembler_h
#define disassembler_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void llvmInitialize(void);
int instrumentASectionWithMapping(uint32_t* baseAddress, uint64_t segmentBase, uint64_t shadowBase,
                                 uint8_t *section_data, size_t section_size);

#ifdef __cplusplus
}
#endif

#endif /* disassembler_h */
