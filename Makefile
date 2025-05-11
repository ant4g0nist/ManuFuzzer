# ManuFuzzer Makefile

# Default target
all: build

# Check for local LLVM build from build_llvm.sh
LOCAL_LLVM_CONFIG_MK = llvm-config-path.mk
ifneq ($(wildcard $(LOCAL_LLVM_CONFIG_MK)),)
  include $(LOCAL_LLVM_CONFIG_MK)
  $(info Found local LLVM config: $(LLVM_CONFIG))
  $(info Found local LibFuzzer object path: $(LIBFUZZER_OBJ_PATH))
else
  # LLVM settings - use system LLVM if available
  LLVM_CONFIG = llvm-config
  LIBFUZZER_OBJ_PATH = llvm-project/compiler-rt/lib/fuzzer
endif

# Check LLVM availability
LLVM_AVAILABLE := $(shell which $(LLVM_CONFIG) >/dev/null 2>&1 && echo 1 || echo 0)

# Compiler settings
CXX = clang++
CC = clang

CXXFLAGS = -ObjC++ -std=c++17 -Wall -Wextra -g
LDFLAGS = -framework Foundation

# Libraries we need from LLVM - restricted to only what we actually build
LLVM_COMPONENTS = Core Support BinaryFormat MC MCParser MCDisassembler AArch64Desc AArch64Info AArch64Disassembler

ifeq ($(LLVM_AVAILABLE), 1)
  # Check if all required libraries are available
  LLVM_CONFIG_OUTPUT := $(shell $(LLVM_CONFIG) --libs $(LLVM_COMPONENTS) 2>&1)
  LLVM_CONFIG_SUCCESS := $(shell $(LLVM_CONFIG) --libs $(LLVM_COMPONENTS) >/dev/null 2>&1 && echo 1 || echo 0)

  ifeq ($(LLVM_CONFIG_SUCCESS), 1)
    # Get both static and dynamic libraries
    LLVM_STATIC_LIBS := $(shell $(LLVM_CONFIG) --libfiles $(LLVM_COMPONENTS))
    LLVM_LIB_PATH := $(shell $(LLVM_CONFIG) --libdir)

    # Check if we have actual library files
    LLVM_LIBS_EXIST := $(shell test -n "$(LLVM_STATIC_LIBS)" && echo 1 || echo 0)

    ifeq ($(LLVM_LIBS_EXIST), 1)
      $(info Using LLVM from: $(LLVM_CONFIG))
      $(info LLVM components: $(LLVM_COMPONENTS))

      CXXFLAGS += -DLLVM_AVAILABLE $(filter-out -fno-exceptions -fno-rtti,$(shell $(LLVM_CONFIG) --cxxflags))
      # Use explicit static libraries instead of dynamic ones to avoid dependency issues
      LDFLAGS += -L$(shell $(LLVM_CONFIG) --libdir) $(shell $(LLVM_CONFIG) --libs $(LLVM_COMPONENTS)) -lz -lcurses
    else
      $(info LLVM library files not found, using fallback implementation)
      $(info Try running: ./build_llvm.sh)
    endif
  else
    $(info LLVM available but required components missing: $(LLVM_CONFIG_OUTPUT))
    $(info Try running: ./build_llvm.sh)
  endif
else
  $(info LLVM not found, using fallback implementation)
  $(info To build LLVM from source, run: ./build_llvm.sh)
endif

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Source files
LIB_MM_SOURCES = $(wildcard $(SRC_DIR)/*.mm)
LIB_CPP_SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
LIB_MM_OBJECTS = $(patsubst $(SRC_DIR)/%.mm,$(BUILD_DIR)/%.o,$(LIB_MM_SOURCES))
LIB_CPP_OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(LIB_CPP_SOURCES))
LIB_OBJECTS = $(LIB_MM_OBJECTS) $(LIB_CPP_OBJECTS)

# Target library and binary
LIB_TARGET = $(BUILD_DIR)/libManuFuzzer.dylib
TEST_HARNESS = $(BIN_DIR)/test_harness

# Check if LibFuzzer object files exist
LIBFUZZER_OBJS_EXIST := $(shell test -d $(LIBFUZZER_OBJ_PATH) && ls $(LIBFUZZER_OBJ_PATH)/*.o >/dev/null 2>&1 && echo 1 || echo 0)
LIBFUZZER_OBJ_FILES = $(wildcard $(LIBFUZZER_OBJ_PATH)/*.o)

# Find specific LibFuzzer objects
FUZZER_DRIVER_OBJ = $(wildcard $(LIBFUZZER_OBJ_PATH)/FuzzerDriver.o)
FUZZER_MAIN_OBJ = $(wildcard $(LIBFUZZER_OBJ_PATH)/FuzzerMain.o)

# Make sure we compile the object files with proper flags for Apple platform
CXXFLAGS += -DLIBFUZZER_APPLE -DFUZZER_NO_MAIN -DFUZZ

# Debug info
ifeq ($(LIBFUZZER_OBJS_EXIST), 1)
  $(info Found LibFuzzer objects at: $(LIBFUZZER_OBJ_PATH))
  $(info Number of LibFuzzer object files: $(words $(LIBFUZZER_OBJ_FILES)))
else
  $(warning LibFuzzer objects not found at $(LIBFUZZER_OBJ_PATH))
endif

# Phony targets
.PHONY: all build clean dirs test test-verbose build_llvm clean_all help test_input check-fuzzer build-font-fuzzer run-font-fuzzer

# Default build target
build: dirs $(LIB_TARGET)

# Create directories
dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)

# Build libManuFuzzer.dylib with LibFuzzer object files directly
$(LIB_TARGET): $(LIB_OBJECTS)
ifeq ($(LIBFUZZER_OBJS_EXIST), 1)
	$(info Building with direct LibFuzzer object files)
	$(info Looking for libFuzzerStart in object files...)
	@nm $(LIBFUZZER_OBJ_PATH)/FuzzerMain.o | grep -i libFuzzerStart || echo "Warning: libFuzzerStart symbol not found!"
	$(CXX) -dynamiclib -o $@ $^ $(LIBFUZZER_OBJ_FILES) -Wl,-exported_symbol,_libFuzzerStart -Wl,-exported_symbol,_installHandlers -Wl,-exported_symbol,_instrumentMe -Wl,-exported_symbol,_manuFuzzerAtExitCleanup $(LDFLAGS)
	@nm $@ | grep -i libFuzzerStart || echo "Warning: libFuzzerStart symbol not found in final library!"
else
	$(info LibFuzzer object files not found, building without fuzzing engine)
	$(CXX) -dynamiclib -o $@ $^ $(LDFLAGS)
	$(warning LibFuzzer objects not found. Run ./build_llvm.sh first for full functionality)
endif
	@echo "Built $(LIB_TARGET)"

# Compile Objective-C++ source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.mm
	$(CXX) $(CXXFLAGS) -I. -c $< -o $@

# Compile C++ source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -I. -c $< -o $@

# Build test harness
$(TEST_HARNESS): examples/test_harness.mm $(LIB_TARGET)
	$(info Building test_harness with integrated LibFuzzer shim)
ifeq ($(LIBFUZZER_OBJS_EXIST), 1)
	$(info Linking test_harness with LibFuzzer from $(LIB_TARGET))
	$(CXX) $(CXXFLAGS) -DFUZZ $(TEST_HARNESS_LOG_FLAGS) -I. -Isrc -o $@ $< -L$(BUILD_DIR) -lManuFuzzer -Wl,-rpath,$(CURDIR)/$(BUILD_DIR) $(LDFLAGS) -framework Foundation -framework CoreGraphics -framework AppKit -framework CoreText -framework Foundation -framework CoreGraphics
else
	$(warning Test harness may not function properly without LibFuzzer objects)
	$(CXX) $(CXXFLAGS) -DFUZZ $(TEST_HARNESS_LOG_FLAGS) -I. -o $@ $< -L$(BUILD_DIR) -lManuFuzzer $(LDFLAGS)
endif
	@if [ -f $(TEST_HARNESS) ]; then \
		install_name_tool -change libManuFuzzer.dylib @executable_path/../build/libManuFuzzer.dylib $(TEST_HARNESS) || true; \
		echo "Built $(TEST_HARNESS)"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Clean complete."

# Clean all build artifacts including LLVM
clean_all: clean
	@echo "Cleaning all build artifacts including LLVM..."
	@rm -rf llvm-build llvm-install $(LOCAL_LLVM_CONFIG_MK)
	@echo "Clean complete."

# Build LLVM and LibFuzzer from source
build_llvm:
	@echo "Building LLVM and LibFuzzer from source..."
	./build_llvm.sh
	@echo "LLVM and LibFuzzer build complete. Now run 'make' to build ManuFuzzer with the local LLVM."

# Create a test input file
test_input: dirs
	@echo "Creating test input file..."
	@mkdir -p $(BIN_DIR)/inputs
	@echo '{"key1":"value1","key2":"value2"}' > $(BIN_DIR)/inputs/test_input.plist
	@echo '["item1","item2"]' > $(BIN_DIR)/inputs/test_array.plist

# Run the test harness
test: $(TEST_HARNESS) test_input
	@echo "Running test harness (filtered output)..."
	@echo "Testing with dictionary input:"
	@$(TEST_HARNESS) $(BIN_DIR)/inputs/test_input.plist 2>&1 | grep -v "^Instrumented branch at" | head -n 20
	@echo "Testing with array input:"
	@$(TEST_HARNESS) $(BIN_DIR)/inputs/test_array.plist 2>&1 | grep -v "^Instrumented branch at" | head -n 20

# Run test harness with verbose output
test-verbose: $(TEST_HARNESS) test_input
	@echo "Running test harness (verbose output)..."
	@echo "Testing with dictionary input:"
	@$(TEST_HARNESS) $(BIN_DIR)/inputs/test_input.plist
	@echo "Testing with array input:"
	@$(TEST_HARNESS) $(BIN_DIR)/inputs/test_array.plist

# Display help information
help:
	@echo "ManuFuzzer Makefile targets:"
	@echo "  make build         - Build libManuFuzzer.dylib and test_harness (default)"
	@echo "  make test          - Run the test harness with filtered output"
	@echo "  make test-verbose  - Run the test harness with full instrumentation output"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make clean_all     - Remove all build artifacts including LLVM"
	@echo "  make build_llvm    - Build LLVM and LibFuzzer from source"
	@echo "  make check-fuzzer  - Check LibFuzzer symbols and object files"
	@echo "  make help          - Display this help message"

# Check LibFuzzer symbols and object files
check-fuzzer:
	@echo "Checking LibFuzzer setup..."
	@echo "LIBFUZZER_OBJ_PATH: $(LIBFUZZER_OBJ_PATH)"
	@echo "Objects exist: $(LIBFUZZER_OBJS_EXIST)"
	@echo "Number of object files: $(words $(LIBFUZZER_OBJ_FILES))"
	@echo "List of object files:"
	@ls -la $(LIBFUZZER_OBJ_PATH)/*.o || echo "No object files found!"
	@echo "Checking for libFuzzerStart symbol in object files..."
	@nm $(LIBFUZZER_OBJ_PATH)/FuzzerMain.o | grep -i libFuzzerStart || echo "Symbol not found in FuzzerMain.o!"
	@echo "Checking symbols in the built library (if exists):"
	@nm $(LIB_TARGET) | grep -i fuzzer || echo "No Fuzzer symbols found in library!"
