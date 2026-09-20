#ifndef AUTH_H
#define AUTH_H

#include <string>

bool auth(const std::string& hash_file, int max_attempts = 3);
std::string passwordHash(const std::string& password);

#endif
