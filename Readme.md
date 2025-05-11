# ManuFuzzer
Binary code-coverage fuzzer for macOS, based on libFuzzer and LLVM

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/ant4g0nist/ManuFuzzer/pulls)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ant4g0nist/ManuFuzzer/blob/main/LICENSE)
[![Follow Twitter](https://img.shields.io/twitter/follow/ant4g0nist?style=social)](https://twitter.com/ant4g0nist)


## What is ManuFuzzer?
ManuFuzzer is an LLVM-based binary, coverage-guided fuzzing framework for macOS. It leverages LLVM's powerful disassembly capabilities and libFuzzer's mutation engine to provide sophisticated binary-only fuzzing. It is simple to integrate coverage-guided fuzzing with ManuFuzzer: just define a special function, update some build flags, and you have instant binary-only, coverage-guided fuzzing with basic-block coverage. Using ManuFuzzer, you can instrument one or more selected frameworks for coverage and fuzz the target functions/library without requiring source code.

## How ManuFuzzer works?
ManuFuzzer makes use of custom breakpoint handlers and LLVM's disassembly capabilities:

1. **Branch Identification**: ManuFuzzer uses LLVM MC to accurately identify branch instructions in the binary.
 
2. **Instrumentation**: When you select a module to instrument, ManuFuzzer replaces branch instructions with breakpoint instructions. If the module resides in the dyld shared cache, ManuFuzzer also identifies and instruments related modules that share memory pages to ensure comprehensive coverage.
 
3. **Shadow Memory**: For each instrumented module (or group of related modules from the dyld cache), ManuFuzzer allocates a dedicated shadow memory region. The original instructions from the instrumented locations are copied to this shadow memory. A dynamic mapping between the original code addresses and their corresponding shadow memory locations is maintained.
 
4. **Runtime Tracking**: Every time a breakpoint (instrumented location) is hit, ManuFuzzer's custom SIGTRAP handler:
    * Looks up the original instruction in the shadow memory using the dynamic mapping.
    * Updates coverage information for that basic-block.
    * Restores the original instruction at the breakpoint location.
    * Resumes execution of the original instruction.
5. **libFuzzer Integration**: Coverage information is shared with libFuzzer to guide the mutation engine towards exploring new code paths.

## How to build ManuFuzzer?
ManuFuzzer depends on LLVM MC for disassembly and LLVM libFuzzer for fuzzing. It applies a custom patch (`llvm_ManuFuzzer.patch`) to enhance LLVM's disassembler for better branch detection and integrate with libFuzzer.

### Clone the repository:
```sh
➜ git clone https://github.com/ant4g0nist/ManuFuzzer
```

### Build LLVM with the custom patch:
```sh
➜ cd ManuFuzzer
➜ ./build_llvm.sh
```

### Build ManuFuzzer (with debug logs):
```sh
➜ make -f Makefile
```

### Build without debug logs:
```sh
➜ FUZZ=1 make -f Makefile
```

## Using ManuFuzzer

ManuFuzzer provides a simple API that makes it easy to integrate coverage-guided fuzzing with any macOS binary target.

### API Reference

The library exports these key functions:

```C
// Set up signal handlers for instrumentation
void installHandlers(void);

// Clean up resources when fuzzing is complete
void libFuzzerCleanUp(void);

// Instrument a target module/framework
int instrumentMe(const char * module);

// Start libFuzzer's mutation engine with a custom test function
int libFuzzerStart(int argc, char **argv, UserCallback LLVMFuzzerTestOneInput);
```

Where `UserCallback` is defined as:
```C
typedef int (*UserCallback)(const uint8_t *Data, size_t Size);
```

### Creating a Fuzzer

To create a fuzzer, follow this pattern:

1. **Initialize handlers** - Call `installHandlers()` to set up breakpoint handlers
2. **Instrument targets** - Call `instrumentMe()` for each framework you want to instrument
3. **Define test function** - Create a function with the `LLVMFuzzerTestOneInput` signature
4. **Start fuzzing** - Call `libFuzzerStart()` with your test function

### Example: Fuzzing CoreGraphics

Here's an example fuzzer targeting the `CGFontCreateWithDataProvider` function:

```cpp
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

#include "libManuFuzzer.h"

extern uint16_t previousLoc;

// Called before fuzzing starts
void LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Set up breakpoint handlers
    installHandlers();

    // Instrument target frameworks
    instrumentMe("/System/Library/Frameworks/ImageIO.framework/Versions/A/ImageIO");
    instrumentMe("/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics");
    instrumentMe("/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText");
    instrumentMe("/System/Library/PrivateFrameworks/FontServices.framework/libFontParser.dylib");
}

// Main fuzzer function - called for each input
int LLVMFuzzerTestOneInput(const uint8_t *fuzz_buff, size_t size)
{
    // Reset coverage tracking for this input
    previousLoc = 0;

    // Skip very small inputs
    if (size < 10) return 0;

    // Create input data from fuzz buffer
    NSData *inData = [[NSData alloc] initWithBytes:fuzz_buff length:size];

    // Call the target function
    CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)inData);
    CGFontRef font = CGFontCreateWithDataProvider(provider);

    // Clean up resources
    if (font)
        CFRelease(font);
    CFRelease(provider);
    [inData release];

    return 0;
}

// Main entry point
int main(int argc, char* argv[])
{
    // Initialize the fuzzer
    LLVMFuzzerInitialize(&argc, &argv);

    // Start libFuzzer's main loop
    libFuzzerStart(argc, argv, LLVMFuzzerTestOneInput);

    // Clean up resources
    libFuzzerCleanUp();

    return 0;
}
```

### Building a Fuzzer

You can compile the example with:

```bash
# Assuming your source is in examples/main.mm
clang++ -ObjC++ -std=c++17 -I./src examples/main.mm -o bin/fuzzer -L./build -lManuFuzzer -framework Foundation -framework CoreGraphics

# Fix dylib path
install_name_tool -change libManuFuzzer.dylib @executable_path/../build/libManuFuzzer.dylib bin/fuzzer
```

### Running a Fuzzer

```bash
# Set library path and run the fuzzer
DYLD_LIBRARY_PATH=./build ./bin/fuzzer -max_len=65536 corpus_dir/
```

This will start fuzzing with libFuzzer, automatically generating and mutating inputs to maximize code coverage.

## Included Examples and Tools

### CoreAudioFuzz
ManuFuzzer includes a sophisticated fuzzer for Apple's CoreAudio framework:

- **Advanced Integration**: Uses LLVM's disassembler for accurate branch detection
- **Full libFuzzer Support**: Leverages mutation-based fuzzing with coverage guidance
- **Multi-Framework Testing**: Instruments CoreAudio, AudioToolbox, and more
- **Easy to Use**: Simple command-line interface with detailed options

To run CoreAudioFuzz:
```sh
➜ cd CoreAudioFuzz
➜ ./run_libfuzzer.sh
```

See `CoreAudioFuzz/README.md` for detailed instructions.

### CoreGraphics Example
An example showing how to fuzz CoreGraphics APIs is included in the `examples` directory.

## Demo
![](demo.gif)

## Features

- **Binary-Only Instrumentation**: No source code required
- **LLVM-Powered Disassembly**: Accurate branch detection across architectures
- **Coverage-Guided Fuzzing**: Integration with libFuzzer's mutation engine
- **Multi-Framework Support**: Instrument multiple frameworks simultaneously
- **Intelligent Dyld Shared Cache Handling**: When instrumenting a framework from the dyld shared cache, ManuFuzzer automatically identifies and instruments other related frameworks that share memory pages, providing more thorough fuzzing.
- **macOS Native**: Built for fuzzing Apple frameworks on macOS

## TODO
- [x] Replace Capstone with LLVM MC
- [x] Add support for macOS on Apple Silicon (M1/M2)
- [x] Integrate with libFuzzer's mutation engine
- [x] Create CoreAudioFuzz example
- [ ] Add support for macOS on Intel
- [ ] Expand documentation and examples
- [ ] Add more fuzzing targets

## Trophies
Let me know if you have found any vulnerabilities using this and will add it here :)

## Thanks 🙌🏻🙌🏻
- [@r3dsm0k3](https://twitter.com/r3dsm0k3)
- [Samuel Groß](https://twitter.com/5aelo)
- [Madhu](https://twitter.com/madhuakula)
- [Google Project Zero Team](https://github.com/googleprojectzero)
