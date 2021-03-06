//
//  utilities.h
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#ifndef utilities_h
#define utilities_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define RESET "\e[0m"

#define pageAlign(addr) (vm_address_t)((uintptr_t)(addr) & (~(vm_page_size - 1)))
#define pageAlignEnd(addr) (vm_address_t) (((addr/vm_page_size)+1) * vm_page_size )

#define shadowMeUp(addr) ((void*)(((uintptr_t)addr) + 0x200000000))

#if FUZZ
    #define dlogn(...)  {}
    #define fatal(...) do { \
        dlogn(RED "[-] PROGRAM ABORT : " RESET __VA_ARGS__); \
        dlogn(RED "         Location" RESET " : %s(), %s:%u\n", \
            __FUNCTION__, __FILE__, __LINE__); \
        exit(1); \
    } while (0)
#else
    #define dlogn(...)  { printf(GRN); printf(__VA_ARGS__); printf(RESET); printf("\n"); }
    #define fatal(...) do { \
        dlogn(RED "[-] PROGRAM ABORT : " RESET __VA_ARGS__); \
        dlogn(RED "         Location" RESET " : %s(), %s:%u\n", \
            __FUNCTION__, __FILE__, __LINE__); \
        exit(1); \
    } while (0)
#endif

#endif