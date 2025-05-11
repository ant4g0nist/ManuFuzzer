#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/stat.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#include <stdlib.h> // For atexit

#include "src/libManuFuzzer.h"

// Declare the cleanup function defined in instrumenter.mm
extern "C" {
    void manuFuzzerAtExitCleanup();
}

// Define debug level
#define DEBUG_LEVEL 0

// Debug helper to print information during fuzzing
#if DEBUG_LEVEL >= 1
#define DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

#if DEBUG_LEVEL >= 2
#define VERBOSE_LOG(...) printf(__VA_ARGS__)
#else
#define VERBOSE_LOG(...)
#endif

// Macros for conditional logging in the main function
#ifdef SILENCE_HARNESS_SETUP_LOGS
    #define HARNESS_PRINTF(...) {}
    #define HARNESS_FPRINTF_STDERR(...) {}
#else
    #define HARNESS_PRINTF(...) printf(__VA_ARGS__)
    #define HARNESS_FPRINTF_STDERR(...) fprintf(stderr, __VA_ARGS__)
#endif

// Globals to track coverage
static int total_fonts_processed = 0;
static int successful_fonts_processed = 0;
static int crashes_detected = 0;
static volatile bool in_font_processing = false;

// JMP buffer for crash recovery
static jmp_buf fontFuzzJmpBuf;

// Signal handler for catching crashes within font processing
static void crash_handler(int sig) {
    if (in_font_processing) {
        DEBUG_LOG("[!] Caught crash (signal %d) during font processing\n", sig);
        crashes_detected++;
        in_font_processing = false;

        // Reset and continue fuzzing
        signal(sig, crash_handler);
        longjmp(fontFuzzJmpBuf, 1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *fuzz_buff, size_t size)
{
    // Require a minimum size to avoid trivial inputs
    if (size < 16) {
        return 0;
    }

    // Set up crash handlers for this fuzzing iteration
    signal(SIGSEGV, crash_handler);
    signal(SIGILL, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGFPE, crash_handler);

    // Create a setjmp context to recover from crashes
    if (setjmp(fontFuzzJmpBuf) != 0) {
        DEBUG_LOG("[*] Recovered from crash in font processing\n");
        return 0;
    }

    in_font_processing = true;

    @autoreleasepool {
        // Create data object from fuzzer buffer
        NSData *fontData = [NSData dataWithBytes:fuzz_buff length:size];

        // Track input processing
        total_fonts_processed++;

        DEBUG_LOG("[+] Processing font data, size: %zu bytes\n", size);

        // Create provider with the font data
        CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)fontData);
        if (!provider) {
            DEBUG_LOG("[-] Failed to create CGDataProvider\n");
            return 0;
        }

        // Attempt to create font from the provider
        CGFontRef font = CGFontCreateWithDataProvider(provider);

        if (font) {
            successful_fonts_processed++;
            DEBUG_LOG("[+] Successfully created font (#%d/%d)\n",
                     successful_fonts_processed, total_fonts_processed);

            // Extract and process font information to trigger more code paths

            // Get font name
            CFStringRef fontName = CGFontCopyFullName(font);
            if (fontName) {
                DEBUG_LOG("[+] Font name: %s\n",
                         CFStringGetCStringPtr(fontName, kCFStringEncodingUTF8) ?
                         CFStringGetCStringPtr(fontName, kCFStringEncodingUTF8) : "[Unknown]");
                CFRelease(fontName);
            }

            // Get number of glyphs
            size_t glyphCount = CGFontGetNumberOfGlyphs(font);
            DEBUG_LOG("[+] Glyph count: %zu\n", glyphCount);

            // Get font metrics
            int ascent = CGFontGetAscent(font);
            int descent = CGFontGetDescent(font);
            int leading = CGFontGetLeading(font);

#if DEBUG_LEVEL >= 1
            DEBUG_LOG("[+] Font metrics - Ascent: %d, Descent: %d, Leading: %d\n",
                     ascent, descent, leading);
#else
            (void)ascent; // Suppress unused variable warning when DEBUG_LEVEL is low
            (void)descent;
            (void)leading;
#endif

            // Try to get glyph data for a few glyphs
            // This forces CoreGraphics to parse more of the font data
            if (glyphCount > 0) {
                for (CGGlyph i = 0; i < MIN(10, glyphCount); i++) {
                    CGRect boundingRect;
                    CGFontGetGlyphBBoxes(font, &i, 1, &boundingRect);
                }
            }

            // Try to get font variation information
            CTFontRef ctFont = CTFontCreateWithGraphicsFont(font, 12.0, NULL, NULL);
            if (ctFont) {
                // Get variation axes
                CFArrayRef variations = CTFontCopyVariationAxes(ctFont);
                if (variations) {
                    DEBUG_LOG("[+] Font has %ld variation axes\n", CFArrayGetCount(variations));

                    // Try to get specific variation instances
                    CFDictionaryRef varInstance = CTFontCopyVariation(ctFont);
                    if (varInstance) {
                        DEBUG_LOG("[+] Font has variation instances\n");
                        CFRelease(varInstance);
                    }

                    CFRelease(variations);
                }

                // Get font features to exercise more code paths
                CFArrayRef features = CTFontCopyFeatures(ctFont);
                if (features) {
                    DEBUG_LOG("[+] Font has %ld feature sets\n", CFArrayGetCount(features));
                    CFRelease(features);
                }

                // Get font traits
                CTFontSymbolicTraits traits = CTFontGetSymbolicTraits(ctFont);
                if (traits) {
                    DEBUG_LOG("[+] Font has symbolic traits: 0x%08X\n", traits);
                }

                CFRelease(ctFont);
            }

            // Get font table tags to exercise font parsing code
            size_t tableCount = CGFontGetNumberOfGlyphs(font);
            if (tableCount > 0) {
                // Try to access various font tables - these trigger different code paths
                const uint32_t tableTags[] = {
                    'cmap', // Character to glyph mapping
                    'glyf', // Glyph data
                    'head', // Font header
                    'hhea', // Horizontal header
                    'hmtx', // Horizontal metrics
                    'loca', // Index to location
                    'maxp', // Maximum profile
                    'name', // Naming table
                    'post', // PostScript information
                    'OS/2', // OS/2 and Windows metrics
                    'kern', // Kerning
                    'CFF ', // Compact Font Format (PostScript)
                    'GPOS', // Glyph positioning
                    'GSUB', // Glyph substitution
                };

                for (size_t i = 0; i < sizeof(tableTags)/sizeof(tableTags[0]); i++) {
                    CFDataRef tableData = CGFontCopyTableForTag(font, tableTags[i]);
                    if (tableData) {
                        DEBUG_LOG("[+] Found table 0x%08X, size: %ld bytes\n",
                                tableTags[i], CFDataGetLength(tableData));
                        CFRelease(tableData);
                    }
                }
            }

            // Release the font
            CFRelease(font);
        } else {
            DEBUG_LOG("[-] Failed to create font\n");
        }

        // Release the provider
        CGDataProviderRelease(provider);
    }

    in_font_processing = false;
    return 0;  // Non-zero return values are reserved for future use
}

int main(int argc, char* argv[])
{
    HARNESS_PRINTF("[*] ManuFuzzer Font Fuzzing Harness\n");
    // Register the cleanup function to be called on normal program termination
    if (atexit(manuFuzzerAtExitCleanup) != 0) {
        HARNESS_FPRINTF_STDERR("[!] Warning: Failed to register atexit cleanup handler.\\n");
        // Not fatal, but good to know.
    }
    HARNESS_PRINTF("[*] Installing signal handlers for coverage collection...\n");
    installHandlers();

    HARNESS_PRINTF("[*] Instrumenting CoreGraphics and font-related frameworks...\n");

    // List of frameworks to instrument for font parsing
    // Adding more specific components of the font parsing subsystem
    const char* frameworks[] = {
        "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics",
        "/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText",
        "/System/Library/PrivateFrameworks/FontServices.framework/libFontParser.dylib",
        "/System/Library/Frameworks/ImageIO.framework/Versions/A/ImageIO",
        "/System/Library/PrivateFrameworks/FontServices.framework/FontServices",
        "/System/Library/PrivateFrameworks/CoreServicesInternal.framework/CoreServicesInternal",
        "/System/Library/PrivateFrameworks/TextureIO.framework/TextureIO",
        NULL
    };

    int frameworkCount = 0;
    int failedCount = 0;

    for (int i = 0; frameworks[i] != NULL; i++) {
        HARNESS_PRINTF("[*] Instrumenting %s\n", frameworks[i]);
        if (instrumentMe(frameworks[i]) == 0) {
            frameworkCount++;
            HARNESS_PRINTF("[+] Successfully instrumented: %s\n", frameworks[i]);
        } else {
            failedCount++;
            printf("[!] Warning: Failed to instrument %s\n", frameworks[i]);
        }
    }

    printf("[+] Successfully instrumented %d frameworks (%d failed)\n", frameworkCount, failedCount);

    // Set fuzzing parameters to improve performance
    char *newArgv[argc + 10]; // Extra space for our additional parameters
    int newArgc = 0;

    // Copy original arguments
    for (int i = 0; i < argc; i++) {
        newArgv[newArgc++] = argv[i];
    }

    // Add fuzzer-specific arguments for better performance
    const char* fuzzerParams[] = {
        "-print_pcs=1",           // Print coverage information
        "-print_final_stats=1",   // Print final statistics
        "-use_value_profile=1",   // Enable value profiling
        "-max_len=1048576",       // Maximum input size (1MB)
        "-timeout=5",             // Timeout in seconds
        NULL
    };

    for (int i = 0; fuzzerParams[i] != NULL; i++) {
        newArgv[newArgc++] = strdup(fuzzerParams[i]);
    }

    printf("[*] Starting fuzzing engine with enhanced parameters...\n");

    // Add common fonts corpus directory if it exists and no corpus is specified
    if (argc == 1) {
        // Check if we have a corpus directory
        const char* corpusDir = "fonts_corpus";
        if (access(corpusDir, F_OK) != -1) {
            printf("[*] Using default corpus directory: %s\n", corpusDir);

            // Add corpus directory to arguments
            newArgv[newArgc++] = strdup(corpusDir);

            // Create output corpus directory for new interesting test cases
            const char* outputDir = "output_corpus";
            mkdir(outputDir, 0755); // Create directory if it doesn't exist
            printf("[*] Using output corpus directory: %s\n", outputDir);

            newArgv[newArgc++] = strdup(outputDir);

            return libFuzzerStart(newArgc, newArgv, LLVMFuzzerTestOneInput);
        }
    }

    // Even if we have custom corpus, add our options
    return libFuzzerStart(newArgc, newArgv, LLVMFuzzerTestOneInput);
}
