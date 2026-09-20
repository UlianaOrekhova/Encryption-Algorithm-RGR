#include "auth.h"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

// Простой детерминированный хэш для учебной проверки пароля.
// Для реальной системы нужен специализированный парольный KDF.
std::string passwordHash(const std::string& password)
{
    uint64_t hash = 14695981039346656037ULL;

    for (unsigned char c : password)
    {
        hash ^= c;
        hash *= 1099511628211ULL;
    }

    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(16)
       << std::setfill('0') << hash;
    return ss.str();
}

bool auth(const std::string& hash_file, int max_attempts)
{
    std::ifstream file(hash_file);
    if (!file)
        throw std::runtime_error("Не удалось прочитать хэш пароля");

    std::string expected;
    std::getline(file, expected);
    if (expected.empty())
        throw std::runtime_error("Файл хэша пароля пуст");

    for (int attempt = 1; attempt <= max_attempts; ++attempt)
    {
        std::string password;
        std::cout << "Введите пароль: ";
        std::getline(std::cin, password);

        if (passwordHash(password) == expected)
        {
            std::cout << "Авторизация успешна.\n";
            return true;
        }

        std::cout << "Неверный пароль. Попытка " << attempt
                  << " из " << max_attempts << ".\n";
    }

    std::cout << "Три неудачные попытки. Завершение работы программы.\n";
    return false;
}
