#ifndef UTIL_H
#define UTIL_H

#include <vector>
#include <cstdint>

void substr(char *dst, char *src, int position, int length);
bool startsWith(const char *pre, const char *str);
std::string trim(const std::string& str);
void print_time();
void print_elapsed_time(std::chrono::time_point<std::chrono::system_clock> start);

#endif
