# Makefile for ManuFuzzer
# Created for ManuFuzzer

CXX = clang++
CC = clang
CXXFLAGS = -ObjC++ -std=c++17 -Wall -Wextra -g
LDFLAGS = -framework Foundation

# LLVM settings - adjust these if needed for your system
LLVM_CONFIG = llvm-config
LLVM_AVAILABLE := $(shell which $(LLVM_CONFIG) >/dev/null 2>&1 && echo 1 || echo 0)

ifeq ($(LLVM_AVAILABLE), 1)
  LLVM_LIBS_AVAILABLE := $(shell $(LLVM_CONFIG) --ldflags --libs core mcparser mcdisassembler >/dev/null 2>&1 && echo 1 || echo 0)
  
  ifeq ($(LLVM_LIBS_AVAILABLE), 1)
    CXXFLAGS += -DLLVM_AVAILABLE $(shell $(LLVM_CONFIG) --cxxflags)
    LDFLAGS += $(shell $(LLVM_CONFIG) --ldflags --system-libs --libs core mcparser mcdisassembler)
    $(info Using LLVM from llvm-config)
  else
    $(info LLVM available but required components missing, using fallback implementation)
  endif
else
  $(info LLVM not found, using fallback implementation)
endif

# Source files
SOURCES = coverage.mm disassembler.mm instrumenter.mm dyld_cache_parser.mm

# Object files
OBJECTS = $(SOURCES:.mm=.o)

# Target library
TARGET = libManuFuzzer.dylib

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) -dynamiclib -o $@ $^ $(LDFLAGS)

%.o: %.mm
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

# Dependencies
coverage.o: coverage.mm coverage.h utilities.h
disassembler.o: disassembler.mm disassembler.h utilities.h
instrumenter.o: instrumenter.mm instrumenter.h utilities.h disassembler.h dyld_cache_parser.h
dyld_cache_parser.o: dyld_cache_parser.mm dyld_cache_parser.h utilities.h
