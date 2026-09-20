#include "auth.h"
#include "file_utils.h"
#include "plugin_loader.h"
#include "console.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
std::filesystem::path executableDirectory(const char* argv0)
{
    if (argv0 == nullptr || *argv0 == '\0')
        return std::filesystem::current_path();

    const std::filesystem::path executable =
        std::filesystem::absolute(std::filesystem::u8path(argv0));
    return executable.parent_path();
}

void saveKey(const std::string& path, const std::vector<uint8_t>& key)
{
    writeFile(path, key);
    std::cout << "Ключ сохранён в: " << path << "\n";
    std::cout << "Ключ: "
              << std::string(key.begin(), key.end()) << "\n";
}

std::vector<uint8_t> loadKey(const std::string& path)
{
    return readFile(path);
}

void generateKey(const Plugin& plugin)
{
    std::string path;
    std::cout << "Введите путь для сохранения ключа: ";
    std::getline(std::cin, path);

    if (path.empty())
        throw std::runtime_error("Путь к ключу не введён");

    std::vector<uint8_t> key = plugin.generateKey();
    saveKey(path, key);
}

void encryptText(const Plugin& plugin)
{
    std::string keyPath;
    std::string text;

    std::cout << "Введите путь к файлу ключа: ";
    std::getline(std::cin, keyPath);
    std::cout << "Введите текст для шифрования: ";
    std::getline(std::cin, text);

    if (text.empty())
        throw std::runtime_error("Пустой текст");

    std::vector<uint8_t> key = loadKey(keyPath);
    std::vector<uint8_t> input(text.begin(), text.end());
    std::vector<uint8_t> result = plugin.encrypt(input, key);

    std::cout << "Шифротекст HEX:\n";
    std::cout << bytesToHex(result) << "\n";
}

void decryptText(const Plugin& plugin)
{
    std::string keyPath;
    std::string hexText;

    std::cout << "Введите путь к файлу ключа: ";
    std::getline(std::cin, keyPath);
    std::cout << "Введите зашифрованные данные в HEX:\n";
    std::getline(std::cin, hexText);

    std::vector<uint8_t> key = loadKey(keyPath);
    std::vector<uint8_t> input = hexToBytes(hexText);
    std::vector<uint8_t> result = plugin.decrypt(input, key);

    std::cout << "Результат дешифрования:\n";
    showAsText(result);
    std::cout << "HEX исходных данных: " << bytesToHex(result) << "\n";
}

void encryptFile(const Plugin& plugin)
{
    std::string keyPath;
    std::string inputPath;
    std::string outputPath;

    std::cout << "Введите путь к файлу ключа: ";
    std::getline(std::cin, keyPath);
    std::cout << "Введите путь к входному файлу: ";
    std::getline(std::cin, inputPath);
    std::cout << "Введите путь к выходному файлу: ";
    std::getline(std::cin, outputPath);

    std::vector<uint8_t> key = loadKey(keyPath);
    std::vector<uint8_t> input = readFile(inputPath);
    std::vector<uint8_t> result = plugin.encrypt(input, key);

    // По ТЗ/отчёту зашифрованный результат сохраняется в HEX.
    std::string hex = bytesToHex(result);
    std::vector<uint8_t> output(hex.begin(), hex.end());
    writeFile(outputPath, output);

    std::cout << "Шифротекст HEX:\n" << hex << "\n";
    std::cout << "Результат сохранён в: " << outputPath << "\n";
}

void decryptFile(const Plugin& plugin)
{
    std::string keyPath;
    std::string inputPath;
    std::string outputPath;

    std::cout << "Введите путь к файлу ключа: ";
    std::getline(std::cin, keyPath);
    std::cout << "Введите путь к зашифрованному файлу (HEX): ";
    std::getline(std::cin, inputPath);
    std::cout << "Введите путь к выходному файлу: ";
    std::getline(std::cin, outputPath);

    std::vector<uint8_t> key = loadKey(keyPath);
    std::vector<uint8_t> hexFile = readFile(inputPath);
    std::string hex(hexFile.begin(), hexFile.end());
    std::vector<uint8_t> input = hexToBytes(hex);
    std::vector<uint8_t> result = plugin.decrypt(input, key);

    writeFile(outputPath, result);

    std::cout << "Результат сохранён в: " << outputPath << "\n";
    showAsText(result);
}

void algorithmMenu(LoadedPlugin& item)
{
    while (true)
    {
        try
        {
            std::cout << "\n " << item.plugin.name() << "\n";
            std::cout << "Библиотека: " << item.file << "\n";
            std::cout << "1. Сгенерировать ключ\n";
            std::cout << "2. Зашифровать текст\n";
            std::cout << "3. Расшифровать текст\n";
            std::cout << "4. Зашифровать файл\n";
            std::cout << "5. Расшифровать файл\n";
            std::cout << "0. Назад\n";
            std::cout << "Выбор: ";

            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "0")
                return;
            if (choice == "1")
                generateKey(item.plugin);
            else if (choice == "2")
                encryptText(item.plugin);
            else if (choice == "3")
                decryptText(item.plugin);
            else if (choice == "4")
                encryptFile(item.plugin);
            else if (choice == "5")
                decryptFile(item.plugin);
            else
                std::cout << "Ошибка! Такого действия нет.\n";
        }
        catch (const std::exception& e)
        {
            std::cout << "[ОШИБКА] " << e.what() << "\n";
        }
    }
}
}

int main(int argc, char* argv[])
{
    try
    {
        initConsole();

        if (argc > 0)
        {
            const std::filesystem::path baseDir = executableDirectory(argv[0]);
            std::error_code ec;
            std::filesystem::current_path(baseDir, ec);
            if (ec)
                throw std::runtime_error("Не удалось перейти в каталог программы: " + baseDir.u8string());
        }

        std::cout << "\n";
        std::cout << "       Encryption Algorithm RGR\n";
        std::cout << "    RSA / Эль-Гамаль / WAKE\n";
        std::cout << "\n";

        // Авторизация выполняется до входа в главное меню.
        if (!auth("password.hash"))
            return 1;

        // После успешной авторизации загружаются все динамические библиотеки.
        const std::filesystem::path baseDir = std::filesystem::current_path();
        std::vector<LoadedPlugin> plugins = loadPlugins(baseDir);

        std::cout << "\nЗагруженные алгоритмы:\n";
        for (std::size_t i = 0; i < plugins.size(); ++i)
            std::cout << i + 1 << ". " << plugins[i].plugin.name()
                      << " -> " << plugins[i].file << "\n";

        while (true)
        {
            try
            {
                std::cout << "\n ГЛАВНОЕ МЕНЮ \n";
                std::cout << "1. RSA\n";
                std::cout << "2. Эль-Гамаль\n";
                std::cout << "3. WAKE\n";
                std::cout << "0. Выход\n";
                std::cout << "Выбор: ";

                std::string choice;
                std::getline(std::cin, choice);

                if (choice == "0")
                {
                    std::cout << "Завершение работы программы. До свидания!\n";
                    break;
                }

                if (choice == "1" || choice == "2" || choice == "3")
                {
                    std::size_t index = static_cast<std::size_t>(choice[0] - '1');
                    algorithmMenu(plugins[index]);
                }
                else
                {
                    std::cout << "Ошибка! Такого действия нет.\n";
                }
            }
            catch (const std::exception& e)
            {
                std::cout << "[ОШИБКА] " << e.what() << "\n";
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cout << "Критическая ошибка: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
