//
//  dyld_cache_parser.h
//  ManuFuzzer
//
//  Created for ManuFuzzer
//

#ifndef ManuFuzzer_DYLD_CACHE_PARSER_H
#define ManuFuzzer_DYLD_CACHE_PARSER_H

#include <map>
#include <string>
#include <vector>

/**
 * Finds the path to the dyld shared cache map file.
 * 
 * @return The path to the dyld shared cache map file
 */
std::string findDyldMap(void);

/**
 * Parses the dyld shared cache map file and returns a mapping of 
 * module names to groups of modules that share pages.
 * 
 * @param path The path to the dyld shared cache map file
 * @return A map where keys are module names and values are vectors of module names that share pages
 */
std::map<std::string, std::vector<std::string>> parseDyldMapFile(const std::string &path);

/**
 * Checks if a module is in the dyld shared cache and returns its group of related modules.
 * 
 * @param moduleName The name of the module to check
 * @return A vector of module names that share pages with the input module, empty if not in cache
 */
std::vector<std::string> getModuleGroup(const std::string &moduleName);

#endif // ManuFuzzer_DYLD_CACHE_PARSER_H