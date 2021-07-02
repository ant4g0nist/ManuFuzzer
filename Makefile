CC 	= clang
CXX = clang++

DESTDIR = /usr/local

ifeq ($(FUZZ),)
	FUZZ := 
else
	FUZZ := -DFUZZ=1
endif

CFLAGS = 
CXXFLAGS = 
FUZZ_EXAMPLE_CFLAGS =  -framework Foundation -framework CoreGraphics -framework AppKit -framework CoreText -framework Foundation -framework CoreGraphics -lManuFuzzer

LLVMFLAGS = -I./llvm-project/llvm/include -I./llvm-project/build/include -std=c++14  -fno-exceptions -fno-rtti -D_DEBUG -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS

LLVMLDFLAGS = -L./llvm-project/build/lib -Wl,-search_paths_first -Wl,-headerpad_max_install_names -lLLVMAArch64AsmParser -lLLVMAArch64Desc -lLLVMAArch64Disassembler -lLLVMAArch64Info -lLLVMAArch64Utils -lLLVMBinaryFormat -lLLVMDebugInfoCodeView -lLLVMDebugInfoMSF -lLLVMDemangle -lLLVMMC -lLLVMMCDisassembler -lLLVMMCParser -lLLVMSupport -lLLVMTableGen -lLLVMTableGenGlobalISel -lz -lpthread -ledit -lcurses -lm

.DEFAULT_GOAL := build
.PHONY: clean examples

llvm_project:
# build llvm-mc and llvm-config
	git clone --branch llvmorg-12.0.1-rc3 https://github.com/llvm/llvm-project
	cd llvm-project && git apply --stat ../llvm_ManuFuzzer.patch && git apply --check ../llvm_ManuFuzzer.patch && git apply ../llvm_ManuFuzzer.patch
	mkdir -p llvm-project/build && cd llvm-project/build && cmake ../llvm && make llvm-config && make llvm-mc

# build libFuzzer
	cd llvm-project/compiler-rt/lib/fuzzer  && ./build.sh

disassembler.o:
	$(shell mkdir bin)
	$(CXX) $(FUZZ) $(LLVMFLAGS) -c -o bin/$@ src/disassembler.mm

coverage.o: src/coverage.mm
	$(CXX) $(FUZZ) $(CXXFLAGS) $(LLVMFLAGS) -c -o bin/$@ src/coverage.mm

instrumenter.o:
	$(CXX) $(FUZZ) $(CXXFLAGS) $(LLVMFLAGS) -c -o bin/$@ src/instrumenter.mm

build: llvm_project disassembler.o coverage.o instrumenter.o
	$(CXX) $(FUZZ)  $(CXXFLAGS) $(LLVMFLAGS) $(LLVMLDFLAGS) ./llvm-project/compiler-rt/lib/fuzzer/*.o bin/*.o -dynamiclib -o bin/libManuFuzzer.dylib
	cp src/libManuFuzzer.h bin/libManuFuzzer.h
	rm bin/*.o

install:
	mkdir -p $(DESTDIR)/lib
	mkdir -p $(DESTDIR)/include
	sudo mv bin/libManuFuzzer.dylib $(DESTDIR)/lib/
	sudo mv bin/libManuFuzzer.h $(DESTDIR)/include/

uninstall:
	rm $(DESTDIR)/include/libManuFuzzer.h
	rm $(DESTDIR)/lib/libManuFuzzer.dylib

example.o: examples/main.mm
	$(CXX) -c -o bin/$@ examples/main.mm
	
example: example.o
	$(CXX) $(FUZZ_EXAMPLE_CFLAGS) ./bin/example.o -o bin/example
	rm bin/*.o
	# ./bin/example seeds/STIXGeneral.ttf

clean:
	rm bin/*
	# rm -rf llvm-project/