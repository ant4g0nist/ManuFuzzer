#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

#include "libManuFuzzer.h"

// used for the coverage
extern uint16_t previousLoc;

int LLVMFuzzerTestOneInput(const uint8_t *fuzz_buff, size_t size)
{
	if (size < 10)
		return 0;

	previousLoc = 0;

	NSData *inData = [[NSData alloc] initWithBytes:fuzz_buff length:size];
	
	CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)inData);
	
	CGFontRef font = CGFontCreateWithDataProvider(provider);
	
	if (font)
	{
		CFRelease(font);
	}
 
	CFRelease(provider);
	[inData release];

	return 0;
}

int main(int argc, char* argv[])
{
	installHandlers();

	instrumentMe("/System/Library/Frameworks/ImageIO.framework/Versions/A/ImageIO");
	instrumentMe("/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics");
	instrumentMe("/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText");
	instrumentMe("/System/Library/PrivateFrameworks/FontServices.framework/libFontParser.dylib");

	libFuzzerStart(argc, argv, LLVMFuzzerTestOneInput);
	libFuzzerCleanUp();

	return 0;
}