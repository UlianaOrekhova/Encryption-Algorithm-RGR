#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> readFile(const std::string& path);
void writeFile(const std::string& path, const std::vector<uint8_t>& data);

std::string bytesToHex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hexToBytes(const std::string& text);

void showAsText(const std::vector<uint8_t>& data);

#endif
