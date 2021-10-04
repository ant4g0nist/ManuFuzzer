//
//  instrumenter.mm
//  ManuFuzzer
//
//  Created by ant4g0nist
//

#include "coverage.h"
#include "utilities.h"
#include "disassembler.h"

#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/swap.h>
#include <mach-o/getsect.h>
#include <mach/machine.h>
#include <mach-o/loader.h>
#import <mach/vm_page_size.h>
#include <mach-o/dyld_images.h>
#include <Foundation/Foundation.h>

task_t task;
extern uint8_t *LibFuzzCounters;
////////////////////////////////////////////////////////////////////////////////
//////////////////////////  MACHO //////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// https://opensource.apple.com/source/dyld/dyld-195.5/include/mach-o/dyld_images.h.auto.html
/*
 *	Beginning in Mac OS X 10.4, this is how gdb discovers which mach-o images are loaded in a process.
 *
 *	gdb looks for the symbol "_dyld_all_image_infos" in dyld.  It contains the fields below.  
 *
 *	For a snashot of what images are currently loaded, the infoArray fields contain a pointer
 *	to an array of all images. If infoArray is NULL, it means it is being modified, come back later.
 *
*/
void* findLibraryLoadAddress(const char* libraryFilePath)
{
	task_dyld_info_data_t task_dyld_info;
	mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;

	kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &dyld_info_count);
	if (kr!=KERN_SUCCESS)
		fatal("failed to get task info");

	const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*) task_dyld_info.all_image_info_addr;

	const struct dyld_image_info* image_infos = all_image_infos->infoArray;

	dlogn("infoArrayCount: %x\n", all_image_infos->infoArrayCount);

	for(size_t i = 0; i < all_image_infos->infoArrayCount; i++)
	{
		const char* imageFilePath = image_infos[i].imageFilePath;
		mach_vm_address_t imageLoadAddress = (mach_vm_address_t)image_infos[i].imageLoadAddress;
		if (strstr(imageFilePath, libraryFilePath))
		{
			return (void*) imageLoadAddress;
		}
	}

	fatal("Failed to find load address of %s", libraryFilePath);
	return NULL;
}

void getMachHeader(void *mach_header_address, struct mach_header_64 *mach_header)
{
	struct mach_header_64* header = (struct mach_header_64*) mach_header_address;
	dlogn("mach_header->magic %x", header->magic);
	*mach_header = *header;
}

void getLoadCommandsBuffer(void *mach_header_address, const struct mach_header_64 *mach_header, void **load_commands)
{
	*load_commands = (void*)((uint64_t)mach_header_address + sizeof(struct mach_header_64));
}

struct section_64 *getSection(void * section_address, const int index, const int swapBytes)
{
	struct section_64 *section = (struct section_64 *) malloc(sizeof(struct section_64));
	memcpy(section, section_address, sizeof(struct section_64));
	
	if (swapBytes)
	{
		swap_section_64(section, 1, NX_UnknownByteOrder);
	}

	return section;	
}

void parseAndInstrument(const char * module, uint32_t* baseAddress)
{
	kern_return_t kr;
	struct mach_header_64 mach_header;
	getMachHeader(baseAddress, &mach_header);

	boolean_t swapBytes = false;
	if (mach_header.magic == MH_CIGAM || mach_header.magic == MH_CIGAM_64 || mach_header.magic == FAT_CIGAM)
		swapBytes = true;	

	void *load_commands_buffer = NULL;
	getLoadCommandsBuffer(baseAddress, &mach_header, &load_commands_buffer);

	uint64_t offset = 0;
	uint32_t moduleSize = 0;

	for (int i = 0; i < mach_header.ncmds; ++i)
	{
		struct load_command *load_cmd = (struct load_command *)((uint64_t)load_commands_buffer + offset);
		struct segment_command_64 *segment_cmd = (struct segment_command_64*) load_cmd;
		
		if (load_cmd->cmd == LC_SEGMENT_64 && strcmp(segment_cmd->segname, "__TEXT") == 0)
		{
			dlogn("base address: %llx", baseAddress);
			uint64_t addr = (uint64_t)(baseAddress + offset);
			uint32_t segSize = pageAlignEnd(segment_cmd->vmsize);
			uint32_t slide  = (uint64_t)baseAddress - segment_cmd->vmaddr;

			//lets' triger COW on module so we can put breakpoints
			kern_return_t kr = vm_protect((vm_map_t)task, (vm_address_t)addr, (vm_size_t)segSize, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

			if (kr != KERN_SUCCESS)
				fatal("failed to make segment addr: %llx as writable", addr);

			uint64_t sections_offset = 0;
			void* sections_base = (void*) ((uint64_t)segment_cmd + sizeof(struct segment_command_64));

            uint8_t* lib_page_start = (uint8_t*)baseAddress;
            if ((uintptr_t)lib_page_start % vm_page_size != 0)
			{
                lib_page_start = (uint8_t*)pageAlign(baseAddress);
            }

			void* shadowAddr =  shadowMeUp(lib_page_start);
			dlogn("Shadow starts at: %llx %lx %lx", (uint64_t ) shadowAddr, segment_cmd->vmsize, pageAlignEnd(0x200000000));

			uint32_t *shadow = (uint32_t *)mmap(shadowAddr, segSize + vm_page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON| MAP_FIXED, 0, 0);

			if(shadow == MAP_FAILED)
			{
				fatal("Failed to mmap shadow memory: %s", strerror(errno));
			}

			for (int isect = 0; isect < segment_cmd->nsects; isect++)
			{	
				uint64_t sect_address = (uint64_t)sections_base + sections_offset;
				struct section_64 * sect = getSection( (void*)( sect_address), isect, swapBytes);
				
				if (sect->flags & S_ATTR_SOME_INSTRUCTIONS || sect->flags & S_ATTR_PURE_INSTRUCTIONS )
				{
					size_t size;
					uint8_t *data = (uint8_t *) getsectiondata((const struct mach_header_64 *)baseAddress, "__TEXT", sect->sectname, &size);
					
					instrumentASection(baseAddress, (uint64_t)shadowAddr, data, size);
				}
				
				free(sect);
				sections_offset += sizeof(struct section_64);
			}

			kr = vm_protect((vm_map_t)task, (vm_address_t)addr, (vm_size_t)segSize, false, VM_PROT_READ | VM_PROT_EXECUTE);
			
			if (kr != KERN_SUCCESS)
				fatal("failed to make segment addr: %llx as executable", addr);

		}
	
		offset += load_cmd->cmdsize;
	}
}

extern "C" int instrumentMe(const char * libraryFilePath)
{   
	llvmInitialize();
	void * loadAddr = findLibraryLoadAddress(libraryFilePath);

	if (!task)
	{
		kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &task);
		if (kr!=KERN_SUCCESS)
			fatal("failed to get task_for_pid");
	}

	parseAndInstrument(libraryFilePath, (uint32_t*)loadAddr);
	dlogn("instrumentMe %s done", libraryFilePath);
	return 0;
}