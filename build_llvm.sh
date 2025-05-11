#!/usr/bin/env bash
set -euo pipefail

echo "Building LLVM for ManuFuzzer - Fixed Version"

# Define LLVM version to build
LLVM_VERSION="14.0.6"
LLVM_COMPONENTS="llvm"

# Clone LLVM if not already present
if [ ! -d "llvm-project" ]; then
    echo "Cloning LLVM repository..."
    git clone --depth 1 --branch llvmorg-$LLVM_VERSION https://github.com/llvm/llvm-project
fi

# Check if patch is already applied
cd llvm-project
PATCH_APPLIED=0
if git diff --quiet -- compiler-rt/lib/fuzzer/FuzzerMain.cpp llvm/include/llvm-c/Disassembler.h llvm/lib/MC/MCDisassembler/Disassembler.cpp; then
    echo "Applying ManuFuzzer patch..."
    git apply ../llvm_ManuFuzzer.patch || { echo "Patch failed to apply! Exiting."; exit 1; }
    # Show patch statistics
    git apply --stat ../llvm_ManuFuzzer.patch
else
    echo "Patch appears to be already applied, skipping..."
    PATCH_APPLIED=1
fi
cd ..

# Build LLVM
mkdir -p llvm-project/build
cd llvm-project/build

echo "Configuring LLVM build..."
# Configure with necessary components - using static libraries for more reliable linking
cmake ../llvm \
    -DLLVM_ENABLE_PROJECTS="${LLVM_COMPONENTS}" \
    -DLLVM_TARGETS_TO_BUILD="X86;AArch64" \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_BUILD_LLVM_DYLIB=OFF \
    -DLLVM_LINK_LLVM_DYLIB=OFF \
    -DBUILD_SHARED_LIBS=OFF

echo "Building LLVM components (this may take a while)..."
# Build specific components needed by ManuFuzzer
cmake --build . --target LLVMCore LLVMSupport LLVMBinaryFormat LLVMMC LLVMMCDisassembler LLVMMCParser

echo "Building AArch64 specific components..."
cmake --build . --target LLVMAArch64Disassembler LLVMAArch64Info LLVMAArch64Desc

echo "Building llvm-config tool..."
cmake --build . --target llvm-config

# Return to LLVM project root
cd ../

# Build LibFuzzer components
echo "Building LibFuzzer components for ManuFuzzer..."

# Use the original LibFuzzer source directory
echo "Compiling LibFuzzer components in-place..."
cd compiler-rt/lib/fuzzer

# Compile all LibFuzzer sources
for f in *.cpp; do
    if [ -f "$f" ]; then
        echo "Compiling $f..."
        # Use LIBFUZZER_APPLE to enable Apple-specific code
        clang++ -std=c++14 -g -O2 -fno-omit-frame-pointer -DLIBFUZZER_APPLE -fPIC -c "$f"
    fi
done

# Skip creating libraries - will use object files directly
echo "LibFuzzer object files are ready for direct use in the ManuFuzzer build"

# Return to project root
cd ../../../

# Create config file for ManuFuzzer Makefile
cat > llvm-config-path.mk << EOF
# Path to local LLVM build
LLVM_CONFIG := \$(CURDIR)/llvm-project/build/bin/llvm-config
# Path to LibFuzzer object files
LIBFUZZER_OBJ_PATH := \$(CURDIR)/llvm-project/compiler-rt/lib/fuzzer
EOF

echo "Creating a custom Makefile for testing LLVM components..."
cat > test_llvm.mk << EOF
# Test Makefile for LLVM components
LLVM_CONFIG := ./llvm-project/build/bin/llvm-config

test-llvm:
	@echo "Testing LLVM configuration..."
	@\$(LLVM_CONFIG) --version
	@echo "Available components:"
	@\$(LLVM_CONFIG) --components
	@echo "Testing core libraries..."
	@\$(LLVM_CONFIG) --libs Core Support MC MCParser MCDisassembler || echo "Failed to get core libraries"
	@echo "Library paths:"
	@\$(LLVM_CONFIG) --libfiles Core Support MC MCParser MCDisassembler || echo "Failed to get library paths"

.PHONY: test-llvm
EOF

echo "LLVM and LibFuzzer build completed!"
echo "Run 'make -f test_llvm.mk test-llvm' to test the LLVM configuration"
echo "Run 'make' to build ManuFuzzer with the new LLVM build"
echo ""
echo "LibFuzzer object files are available at: llvm-project/compiler-rt/lib/fuzzer/*.o"
echo "Use them directly in your compilation like:"
echo "  \$(CXX) \$(CXXFLAGS) \$(LLVMFLAGS) \$(LLVMLDFLAGS) ./llvm-project/compiler-rt/lib/fuzzer/*.o bin/*.o -dynamiclib -o bin/libManuFuzzer.dylib"