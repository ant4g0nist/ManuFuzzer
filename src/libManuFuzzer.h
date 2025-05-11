//
//  libManuFuzzer.h
//  libManuFuzzer
//
//  Created by ant4g0nist
//

#ifndef LIBManuFuzzer_H
#define LIBManuFuzzer_H

#include <stddef.h>
#include <stdint.h>

typedef int (*UserCallback)(const uint8_t *Data, size_t Size);

extern "C" {
    void installHandlers(void);
    void libFuzzerCleanUp(void);
    int instrumentASectionWithMapping(uint32_t* baseAddress, uint64_t segmentBase, uint64_t shadowBase,
                                     uint8_t *section_data, size_t section_size);
    int libFuzzerStart(int argc, char **argv, UserCallback LLVMFuzzerTestOneInput);
}

#endif
