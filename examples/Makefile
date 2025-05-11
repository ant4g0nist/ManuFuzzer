# ManuFuzzer examples Makefile

# Compiler settings
CXX = clang++
CXXFLAGS = -ObjC++ -std=c++17 -Wall -g
LDFLAGS = -framework Foundation -framework CoreGraphics -framework CoreServices

# Directories
BUILD_DIR = ../build
BIN_DIR = ../bin
EXAMPLES_BIN_DIR = $(BIN_DIR)/examples

# ManuFuzzer library
MANUFUZZER_LIB = $(BUILD_DIR)/libManuFuzzer.dylib
MANUFUZZER_INCLUDE = -I..

# Targets
all: dirs simple_test

# Create directories
dirs:
	@mkdir -p $(EXAMPLES_BIN_DIR)

# Compile simple_test example
simple_test: simple_test.mm $(MANUFUZZER_LIB)
	$(CXX) $(CXXFLAGS) $(MANUFUZZER_INCLUDE) -o $(EXAMPLES_BIN_DIR)/$@ $< -L$(BUILD_DIR) -lManuFuzzer $(LDFLAGS)
	install_name_tool -change libManuFuzzer.dylib @executable_path/../../build/libManuFuzzer.dylib $(EXAMPLES_BIN_DIR)/$@ || true
	@echo "Built $(EXAMPLES_BIN_DIR)/$@"

# Compile CoreAudio fuzzer example
coreaudio: coreaudio_fuzzer.mm $(MANUFUZZER_LIB)
	$(CXX) $(CXXFLAGS) $(MANUFUZZER_INCLUDE) -o $(EXAMPLES_BIN_DIR)/$@ $< -L$(BUILD_DIR) -lManuFuzzer $(LDFLAGS) -framework CoreAudio
	install_name_tool -change libManuFuzzer.dylib @executable_path/../../build/libManuFuzzer.dylib $(EXAMPLES_BIN_DIR)/$@ || true
	@echo "Built $(EXAMPLES_BIN_DIR)/$@"

# Clean
clean:
	rm -rf $(EXAMPLES_BIN_DIR)

# Phony targets
.PHONY: all dirs clean