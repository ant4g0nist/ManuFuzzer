# Path to local LLVM build
LLVM_CONFIG := $(CURDIR)/llvm-project/build/bin/llvm-config
# Path to LibFuzzer object files
LIBFUZZER_OBJ_PATH := $(CURDIR)/llvm-project/compiler-rt/lib/fuzzer