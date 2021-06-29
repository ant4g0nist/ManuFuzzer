//
//  coverage.m
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#include "coverage.h"
#include "utilities.h"
#include <mach/vm_page_size.h>
#include <libkern/OSCacheControl.h>
#include <Foundation/Foundation.h>


extern task_t task;
uint16_t previousLoc = 0;
uint8_t *LibFuzzCounters;
// struct configs configList;

extern void sys_icache_invalidate( void *start, size_t len);

void dump_registers(ucontext_t* uc)
{
 printf( "\n"
	"x0:%016lx x1:%016lx x2:%016lx x3:%016lx\n"
	"x4:%016lx x5:%016lx x6:%016lx x7:%016lx\n"
	"x8:%016lx x9:%016lx x10:%016lx x11:%016lx\n"
	"x12:%016lx x13:%016lx x14:%016lx x15:%016lx\n"
	"x16:%016lx x17:%016lx x18:%016lx x19:%016lx\n"
	"x20:%016lx x21:%016lx x22:%016lx x23:%016lx\n"
	"x24:%016lx x25:%016lx x26:%016lx x27:%016lx\n"
	"x28:%016lx fp:%016lx lr:%016lx\n"
	"sp:%016lx pc:%016lx cpsr:%08lx\n",
		(unsigned long) uc->uc_mcontext->__ss.__x[0],
		(unsigned long) uc->uc_mcontext->__ss.__x[1],
		(unsigned long) uc->uc_mcontext->__ss.__x[2],
		(unsigned long) uc->uc_mcontext->__ss.__x[3],
		(unsigned long) uc->uc_mcontext->__ss.__x[4],
		(unsigned long) uc->uc_mcontext->__ss.__x[5],
		(unsigned long) uc->uc_mcontext->__ss.__x[6],
		(unsigned long) uc->uc_mcontext->__ss.__x[7],
		(unsigned long) uc->uc_mcontext->__ss.__x[8],
		(unsigned long) uc->uc_mcontext->__ss.__x[9],
		(unsigned long) uc->uc_mcontext->__ss.__x[10],
		(unsigned long) uc->uc_mcontext->__ss.__x[11],
		(unsigned long) uc->uc_mcontext->__ss.__x[12],
		(unsigned long) uc->uc_mcontext->__ss.__x[13],
		(unsigned long) uc->uc_mcontext->__ss.__x[14],
		(unsigned long) uc->uc_mcontext->__ss.__x[15],
		(unsigned long) uc->uc_mcontext->__ss.__x[16],
		(unsigned long) uc->uc_mcontext->__ss.__x[17],
		(unsigned long) uc->uc_mcontext->__ss.__x[18],
		(unsigned long) uc->uc_mcontext->__ss.__x[19],
		(unsigned long) uc->uc_mcontext->__ss.__x[20],
		(unsigned long) uc->uc_mcontext->__ss.__x[21],
		(unsigned long) uc->uc_mcontext->__ss.__x[22],
		(unsigned long) uc->uc_mcontext->__ss.__x[23],
		(unsigned long) uc->uc_mcontext->__ss.__x[24],
		(unsigned long) uc->uc_mcontext->__ss.__x[25],
		(unsigned long) uc->uc_mcontext->__ss.__x[26],
		(unsigned long) uc->uc_mcontext->__ss.__x[27],
		(unsigned long) uc->uc_mcontext->__ss.__x[28],
		(unsigned long) arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
		(unsigned long) arm_thread_state64_get_lr(uc->uc_mcontext->__ss),
		(unsigned long) arm_thread_state64_get_sp(uc->uc_mcontext->__ss),
		(unsigned long) arm_thread_state64_get_pc(uc->uc_mcontext->__ss),
		(unsigned long) uc->uc_mcontext->__ss.__cpsr);
}

//TODO: AFL's Blindspot and How to Resist AFL Fuzzing for Arbitrary ELF Binaries
void updateCoverage(uint64_t curLoc)
{
	curLoc  = ( (curLoc >> 4) ^ (curLoc << 8) ) & (MAP_SIZE - 1);
	LibFuzzCounters[curLoc ^ previousLoc]++;
	previousLoc = previousLoc >> 1;
}

static void coverageHandler(int signum, siginfo_t* info, void* context)
{
	dlogn("== coverageHandler start");
	kern_return_t kr;

	uint32_t* fault_addr = (uint32_t*)info->si_addr;
	uint32_t *shadow 	 = (uint32_t*)shadowMeUp(fault_addr);
	
	dlogn("coverage_handler: fault_addr : %llx shadowAddr : %llx ", fault_addr, shadow);

	updateCoverage((uint64_t) fault_addr);

    if (mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_WRITE) != 0) 
        fatal("Failed to mprotect %p writable", fault_addr);

	uint32_t orig_byte = *shadow;
	dlogn("orig_byte: %x", orig_byte);

	*fault_addr = orig_byte;

	sys_icache_invalidate(fault_addr, 4);
	__asm__ volatile("dmb ishst" ::: "memory");

	if (mprotect((void*)pageAlign(fault_addr), vm_page_size, PROT_READ | PROT_EXEC) != 0)
        fatal("Failed to mprotect %p executable", fault_addr);

	dlogn("== coverageHandler end");
}


extern "C" void installHandlers()
{
	dlogn("Installing handlers");

	struct sigaction s;
	s.sa_flags = SA_SIGINFO;
	s.sa_sigaction = coverageHandler;
	
	sigemptyset(&s.sa_mask);
	sigaction(SIGTRAP, &s, 0);

	LibFuzzCounters = (uint8_t *) malloc(sizeof(uint8_t)*MAP_SIZE);
	memset(LibFuzzCounters, 0, sizeof(uint8_t)*MAP_SIZE);

	dlogn("Installed handlers");
}

extern "C" int libFuzzerCleanUp()
{
	free(LibFuzzCounters);
	return 0;
}