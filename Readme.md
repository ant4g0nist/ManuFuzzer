# ManuFuzzer
Binary code-coverage fuzzer for macOS, based on libFuzzer and LLVM

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/ant4g0nist/ManuFuzzer/pulls)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ant4g0nist/ManuFuzzer/blob/main/LICENSE)
[![Follow Twitter](https://img.shields.io/twitter/follow/ant4g0nist?style=social)](https://twitter.com/ant4g0nist)


## What is ManuFuzzer?
ManuFuzzer is an LLVM-based binary, coverage-guided fuzzing framework similar. It is simple to integrate coverage-guided fuzzing with ManuFuzzer: just define a special function, update some build flags, and you have instant binary-only, coverage-guided fuzzing (only basic-block coverage). Using ManuFuzzer, you can instrument one or more selected frameworks for coverage and fuzz the target functions/library.

## How ManuFuzzer works?
ManuFuzzer makes use of custom breakpoint handler. When you select a module to instrument, ManuFuzzer replaces the branch instructions with breakpoint instruction at each and every basic-block by disassembling the module runtime using LLVM MC and stores the original bytes in a shadow memory mapping, whose address is fixed and can be computed from any address of the modified library and executes the program. Everytime any breakpoint gets hit, ManuFuzzer updates the coverage for the basic-block using custom breakpoint handler setup for SIGTRAP, deletes the breakpoint and resumes execution.

## How to build ManuFuzzer?
ManuFuzzer is dependent on LLVM MC for disassembly and LLVM libFuzzer for fuzzing. ManuFuzzer patches LLVM-MC to increase the speed and evaluate an instruction type. ManuFuzzer pulls LLVM version 12.0.1-rc3 from https://github.com/llvm/llvm-project and applies llvm_ManuFuzzer.patch to LLVM MC and libFuzzer.

```sh
➜ git clone https://github.com/ant4g0nist/ManuFuzzer
```

To compile with debug logs:
```sh
➜ cd ManuFuzzer
➜ make
➜ make install
```

To compile without debug logs, pass FUZZ=1 in env:
```sh
➜ cd ManuFuzzer
➜ FUZZ=1 make
➜ make install
```

## How to use ManuFuzzer?
For examples, let's try fuzzing CGFontCreateWithDataProvider function from CoreGraphics. This seems to be an easy target to reach.

ManuFuzzer exports 4 functions we need to use in our harness.

```C
void installHandlers(void);
void libFuzzerCleanUp(void);
int instrumentMe(const char * module);
int libFuzzerStart(int argc, char **argv, UserCallback LLVMFuzzerTestOneInput);
```

- `instrumentMe(const char * module)` function is used to instrument a target module. 
- `installHandlers` function installs the breakpoint handler required by ManuFuzzer to handle breakpoints.
- `libFuzzerStart` is the main entry point to libFuzzer that takes argc, argv and a function `LLVMFuzzerTestOneInput` with signature `LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)`
- `libFuzzerCleanUp` just cleans up the mallocs.

These functions can be used in our harness as shown here:

```CPP
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

#include "libManuFuzzer.h"

extern uint16_t previousLoc;

void LLVMFuzzerInitialize(int *argc, char ***argv) {
    installHandlers();

    instrumentMe("/System/Library/Frameworks/ImageIO.framework/Versions/A/ImageIO");
    instrumentMe("/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics");
    instrumentMe("/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText");
    instrumentMe("/System/Library/PrivateFrameworks/FontServices.framework/libFontParser.dylib");
}

int LLVMFuzzerTestOneInput(const uint8_t *fuzz_buff, size_t size)
{
    previousLoc = 0;

    NSData *inData = [[NSData alloc] initWithBytes:fuzz_buff length:size];
    CFErrorRef error;
    
    CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)inData);
    
    CGFontRef font = CGFontCreateWithDataProvider(provider);
    
    if (font)
        CFRelease(font);
 
    CFRelease(provider);

    [inData release];

    return 0;
}

int main(int argc, char* argv[])
{
    LLVMFuzzerInitialize(&argc, &argv);
    libFuzzerStart(argc, argv, LLVMFuzzerTestOneInput);
    libFuzzerCleanUp();

    return 0;
}
```

Makefile to compile above sample code:
```make
example.o: examples/main.mm
	SDKROOT=$(SDKROOT) $(CXX) -c -o bin/$@ examples/main.mm
	
example: example.o
	SDKROOT=$(SDKROOT) $(CXX) $(FUZZ_EXAMPLE_CFLAGS) ./bin/example.o -o bin/example
	rm bin/*.o
```

To compile the example:
```sh
➜ make example
```

## Demo
![](demo.gif)


## TODO
- [x] replace Capstone with LLVM MC
- [x] make support for macOS on M1 public
- [ ] make support for macOS on Intel public
- [ ] clean the setup
- [ ] test, test and tesssttt
- [ ] fuzz, fuzzzz and more fuzzzzz

## Trofies
let me know if you have found any vulnerabilities using this and will add it here :)

## Thanks 🙌🏻🙌🏻
- [@r3dsm0k3](https://twitter.com/r3dsm0k3) 
- [Samuel Groß](https://twitter.com/5aelo)
- [Madhu](https://twitter.com/madhuakula)