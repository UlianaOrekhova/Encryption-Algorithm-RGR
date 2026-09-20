#include "file_utils.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

std::vector<uint8_t> readFile(const std::string& path)
{
    const fs::path filePath = fs::u8path(path);
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        throw std::runtime_error("Не удалось открыть файл: " + path);

    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), {});
}

void writeFile(const std::string& path, const std::vector<uint8_t>& data)
{
    const fs::path p = fs::u8path(path);
    if (p.has_parent_path())
    {
        std::error_code ec;
        fs::create_directories(p.parent_path(), ec);
        if (ec)
            throw std::runtime_error("Не удалось создать каталог для выходного файла");
    }

    const fs::path filePath = fs::u8path(path);
    std::ofstream file(filePath, std::ios::binary);
    if (!file)
        throw std::runtime_error("Не удалось создать выходной файл: " + path);

    if (!data.empty())
        file.write(reinterpret_cast<const char*>(data.data()),
                   static_cast<std::streamsize>(data.size()));
}

std::string bytesToHex(const std::vector<uint8_t>& data)
{
    std::stringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0');

    for (uint8_t b : data)
        ss << std::setw(2) << static_cast<unsigned int>(b);

    return ss.str();
}

static int hexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<uint8_t> hexToBytes(const std::string& text)
{
    std::string s;
    for (char c : text)
        if (!std::isspace(static_cast<unsigned char>(c)))
            s += c;

    if (s.empty())
        throw std::runtime_error("Пустая HEX-строка");
    if (s.size() % 2 != 0)
        throw std::runtime_error("HEX-строка должна содержать чётное число символов");

    std::vector<uint8_t> result;
    result.reserve(s.size() / 2);

    for (size_t i = 0; i < s.size(); i += 2)
    {
        int a = hexValue(s[i]);
        int b = hexValue(s[i + 1]);
        if (a < 0 || b < 0)
            throw std::runtime_error("Некорректный HEX-символ");
        result.push_back(static_cast<uint8_t>(a * 16 + b));
    }

    return result;
}

void showAsText(const std::vector<uint8_t>& data)
{
    // Treat valid UTF-8 as printable text. The previous implementation only
    // accepted ASCII bytes, so any Cyrillic text was reported as binary data.
    std::size_t i = 0;
    while (i < data.size())
    {
        const uint8_t b0 = data[i];

        if (b0 == '\n' || b0 == '\r' || b0 == '\t' ||
            (b0 >= 0x20 && b0 <= 0x7E))
        {
            ++i;
            continue;
        }

        std::size_t length = 0;
        uint32_t codePoint = 0;
        if (b0 >= 0xC2 && b0 <= 0xDF)
        {
            length = 2;
            codePoint = b0 & 0x1F;
        }
        else if (b0 >= 0xE0 && b0 <= 0xEF)
        {
            length = 3;
            codePoint = b0 & 0x0F;
        }
        else if (b0 >= 0xF0 && b0 <= 0xF4)
        {
            length = 4;
            codePoint = b0 & 0x07;
        }
        else
        {
            std::cout << "Результат содержит непечатаемые байты.\n";
            return;
        }

        if (i + length > data.size())
        {
            std::cout << "Результат содержит непечатаемые байты.\n";
            return;
        }

        for (std::size_t j = 1; j < length; ++j)
        {
            if ((data[i + j] & 0xC0) != 0x80)
            {
                std::cout << "Результат содержит непечатаемые байты.\n";
                return;
            }
            codePoint = (codePoint << 6) | (data[i + j] & 0x3F);
        }

        if ((length == 2 && codePoint < 0x80) ||
            (length == 3 && codePoint < 0x800) ||
            (length == 4 && codePoint < 0x10000) ||
            codePoint > 0x10FFFF ||
            (codePoint >= 0xD800 && codePoint <= 0xDFFF))
        {
            std::cout << "Результат содержит непечатаемые байты.\n";
            return;
        }

        i += length;
    }

    std::cout << "Текст: " << std::string(data.begin(), data.end()) << '\n';
}

