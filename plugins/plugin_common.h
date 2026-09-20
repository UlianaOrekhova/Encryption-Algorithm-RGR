#ifndef PLUGIN_COMMON_H
#define PLUGIN_COMMON_H

#include "plugin_api.h"

#include <cctype>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace plugin_common
{
// The application is single-threaded. A plain module-local string avoids
// MinGW/Windows TLS initialization issues when the DLL is loaded.
inline std::string last_error;

inline void setError(const std::string& text)
{
    last_error = text;
}

inline void clearError()
{
    last_error.clear();
}

inline const char* error()
{
    return last_error.c_str();
}

inline int finishKey(const std::string& text, MutBuffer* key)
{
    if (!key)
    {
        setError("Некорректные параметры генерации ключа");
        return 1;
    }

    key->size = text.size();
    key->data = new uint8_t[key->size];
    for (std::size_t i = 0; i < key->size; ++i)
        key->data[i] = static_cast<uint8_t>(text[i]);

    return 0;
}

inline int finish(const std::vector<uint8_t>& data, MutBuffer* out)
{
    if (!out)
    {
        setError("Некорректные параметры результата");
        return 1;
    }

    out->size = data.size();
    out->data = new uint8_t[out->size];
    for (std::size_t i = 0; i < out->size; ++i)
        out->data[i] = data[i];

    return 0;
}

inline std::vector<std::string> split(const std::string& text)
{
    std::stringstream ss(text);
    std::vector<std::string> result;
    std::string word;

    while (ss >> word)
        result.push_back(word);

    return result;
}

inline bool isNumber(const std::string& text)
{
    if (text.empty())
        return false;

    for (unsigned char c : text)
        if (!std::isdigit(c))
            return false;

    return true;
}

inline int hexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

inline std::vector<uint8_t> hexToBytes(const std::string& text)
{
    std::string s;
    for (char c : text)
        if (!std::isspace(static_cast<unsigned char>(c)))
            s += c;

    if (s.empty() || s.size() % 2 != 0)
        throw std::runtime_error("Некорректная HEX-строка");

    std::vector<uint8_t> result;
    result.reserve(s.size() / 2);

    for (std::size_t i = 0; i < s.size(); i += 2)
    {
        int a = hexValue(s[i]);
        int b = hexValue(s[i + 1]);
        if (a < 0 || b < 0)
            throw std::runtime_error("Некорректный HEX-символ");
        result.push_back(static_cast<uint8_t>(a * 16 + b));
    }

    return result;
}

inline std::string bytesToHex(const std::vector<uint8_t>& data)
{
    std::stringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0');
    for (uint8_t b : data)
        ss << std::setw(2) << static_cast<unsigned int>(b);
    return ss.str();
}

inline uint64_t modPow(uint64_t a, uint64_t e, uint64_t mod)
{
    uint64_t result = 1;
    a %= mod;

    while (e > 0)
    {
        if (e & 1)
            result = (result * a) % mod;
        a = (a * a) % mod;
        e >>= 1;
    }

    return result;
}

inline int64_t gcdInt(int64_t a, int64_t b)
{
    while (b != 0)
    {
        int64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

inline int64_t modInverse(int64_t a, int64_t m)
{
    int64_t oldR = a, r = m;
    int64_t oldS = 1, s = 0;

    while (r != 0)
    {
        int64_t q = oldR / r;

        int64_t t = oldR - q * r;
        oldR = r;
        r = t;

        t = oldS - q * s;
        oldS = s;
        s = t;
    }

    if (oldR != 1)
        throw std::runtime_error("Обратного элемента не существует");

    oldS %= m;
    if (oldS < 0)
        oldS += m;

    return oldS;
}

inline std::mt19937& generator()
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    return gen;
}

inline uint32_t random32()
{
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFFu);
    return dist(generator());
}

inline uint32_t randomUInt(uint32_t left, uint32_t right)
{
    std::uniform_int_distribution<uint32_t> dist(left, right);
    return dist(generator());
}
}

#endif
