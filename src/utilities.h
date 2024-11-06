//
//  utilities.h
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#ifndef MANUFUZZER_UTILITIES_H
#define MANUFUZZER_UTILITIES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <mach/vm_page_size.h>

////////////////////////////////////////////////////////////////////////////////
// Constants and Macros
////////////////////////////////////////////////////////////////////////////////

// ANSI color codes for logging
#define ANSI_RED     "\e[0;31m"
#define ANSI_GREEN   "\e[0;32m"
#define ANSI_YELLOW  "\e[0;33m"
#define ANSI_BLUE    "\e[0;34m"
#define ANSI_MAGENTA "\e[0;35m"
#define ANSI_CYAN    "\e[0;36m"
#define ANSI_RESET   "\e[0m"

// Version information
#define MANUFUZZER_VERSION_MAJOR 1
#define MANUFUZZER_VERSION_MINOR 0
#define MANUFUZZER_VERSION_PATCH 0

// Memory constants
#define SHADOW_MEMORY_OFFSET 0x200000000

////////////////////////////////////////////////////////////////////////////////
// Type Definitions
////////////////////////////////////////////////////////////////////////////////

// Status codes for operations
enum class Status {
    Success = 0,
    Error = -1,
    MemoryError = -2,
    InvalidArgument = -3,
    NotInitialized = -4
};

// Configuration structure
struct Config {
    bool debugMode;
    bool verboseLogging;
    uint32_t timeoutMs;
    size_t maxMemory;
};

////////////////////////////////////////////////////////////////////////////////
// Memory Management
////////////////////////////////////////////////////////////////////////////////

// Page alignment utilities
inline vm_address_t pageAlign(const void* addr) {
    return (vm_address_t)((uintptr_t)(addr) & (~(vm_page_size - 1)));
}

inline vm_address_t pageAlignEnd(size_t addr) {
    return (vm_address_t)(((addr/vm_page_size) + 1) * vm_page_size);
}

// Shadow memory mapping
inline void* shadowMeUp(const void* addr) {
    return (void*)(((uintptr_t)addr) + SHADOW_MEMORY_OFFSET);
}

// Memory validation
inline bool isAligned(const void* addr, size_t alignment) {
    return (((uintptr_t)addr) & (alignment - 1)) == 0;
}

inline bool isValidAddress(const void* addr, size_t size) {
    return addr != nullptr && ((uintptr_t)addr + size) > (uintptr_t)addr;
}

////////////////////////////////////////////////////////////////////////////////
// Logging and Debug Utilities
////////////////////////////////////////////////////////////////////////////////

#if FUZZ
    // Minimal logging in fuzzing mode
    #define dlogn(...) ((void)0)
    
    #define fatal(...) do { \
        exit(1); \
    } while (0)

#else
    // Full logging in debug mode
    #define dlogn(...) do { \
        printf(ANSI_GREEN); \
        printf(__VA_ARGS__); \
        printf(ANSI_RESET); \
        printf("\n"); \
    } while (0)

    #define fatal(...) do { \
        fprintf(stderr, ANSI_RED "[-] PROGRAM ABORT : " ANSI_RESET); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n" ANSI_RED "         Location : %s(), %s:%u\n" ANSI_RESET, \
                __FUNCTION__, __FILE__, __LINE__); \
        exit(1); \
    } while (0)
#endif

// Debug logging with different levels
#ifndef FUZZ
    #define debug_info(...) dlogn(ANSI_BLUE "[INFO] " ANSI_RESET __VA_ARGS__)
    #define debug_warn(...) dlogn(ANSI_YELLOW "[WARN] " ANSI_RESET __VA_ARGS__)
    #define debug_error(...) dlogn(ANSI_RED "[ERROR] " ANSI_RESET __VA_ARGS__)
    #define debug_success(...) dlogn(ANSI_GREEN "[SUCCESS] " ANSI_RESET __VA_ARGS__)
#else
    #define debug_info(...) ((void)0)
    #define debug_warn(...) ((void)0)
    #define debug_error(...) ((void)0)
    #define debug_success(...) ((void)0)
#endif

////////////////////////////////////////////////////////////////////////////////
// String Utilities
////////////////////////////////////////////////////////////////////////////////

// Safe string operations
inline size_t safe_strlen(const char* str, size_t maxlen) {
    return str ? strnlen(str, maxlen) : 0;
}

inline char* safe_strncpy(char* dest, const char* src, size_t n) {
    if (!dest || !src || n == 0) return dest;
    
    strncpy(dest, src, n - 1);
    dest[n - 1] = '\0';
    return dest;
}

////////////////////////////////////////////////////////////////////////////////
// Bit Manipulation
////////////////////////////////////////////////////////////////////////////////

// Bit manipulation utilities
inline uint32_t rotateLeft(uint32_t value, unsigned int count) {
    return (value << count) | (value >> (32 - count));
}

inline uint32_t rotateRight(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

inline bool isPowerOfTwo(uintptr_t x) {
    return x && !(x & (x - 1));
}

inline uintptr_t roundUpPowerTwo(uintptr_t x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x++;
    return x;
}

////////////////////////////////////////////////////////////////////////////////
// Error Handling
////////////////////////////////////////////////////////////////////////////////

// Error checking utilities
inline const char* statusToString(Status status) {
    switch (status) {
        case Status::Success: return "Success";
        case Status::Error: return "Error";
        case Status::MemoryError: return "Memory Error";
        case Status::InvalidArgument: return "Invalid Argument";
        case Status::NotInitialized: return "Not Initialized";
        default: return "Unknown Error";
    }
}

inline void checkError(Status status, const char* message) {
    if (status != Status::Success) {
        fatal("%s: %s", message, statusToString(status));
    }
}

////////////////////////////////////////////////////////////////////////////////
// System Utilities
////////////////////////////////////////////////////////////////////////////////

// System information utilities
inline bool isLittleEndian() {
    static const uint16_t endianTest = 1;
    return *((uint8_t*)&endianTest) == 1;
}

inline uint64_t getSystemPageSize() {
    return vm_page_size;
}

////////////////////////////////////////////////////////////////////////////////
// Cleanup Utilities
////////////////////////////////////////////////////////////////////////////////

// RAII-style cleanup helper
template<typename T>
class ScopedCleanup {
private:
    T& resource;
    void (*cleanup)(T&);

public:
    ScopedCleanup(T& r, void (*c)(T&)) : resource(r), cleanup(c) {}
    ~ScopedCleanup() { if (cleanup) cleanup(resource); }
    
    // Prevent copying
    ScopedCleanup(const ScopedCleanup&) = delete;
    ScopedCleanup& operator=(const ScopedCleanup&) = delete;
};

#endif /* MANUFUZZER_UTILITIES_H */