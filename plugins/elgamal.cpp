#include "plugin_common.h"

#include <stdexcept>

namespace
{
struct ElGamalKey
{
    uint32_t p = 467;
    uint32_t g = 2;
    uint32_t x = 0;
    uint32_t y = 0;
};

ElGamalKey generateKey()
{
    ElGamalKey key;
    key.p = 467; // простое число > 255 для учебной побайтовой схемы
    key.g = 2;
    key.x = plugin_common::randomUInt(2, key.p - 2);
    key.y = static_cast<uint32_t>(plugin_common::modPow(key.g, key.x, key.p));
    return key;
}

ElGamalKey readKey(const uint8_t* key, std::size_t key_size)
{
    std::string text(reinterpret_cast<const char*>(key), key_size);
    std::vector<std::string> v = plugin_common::split(text);

    if (v.size() != 4)
        throw std::runtime_error("Неверный формат ключа Эль-Гамаля");

    for (const std::string& value : v)
        if (!plugin_common::isNumber(value))
            throw std::runtime_error("Неверный формат ключа Эль-Гамаля");

    ElGamalKey result;
    result.p = static_cast<uint32_t>(std::stoul(v[0]));
    result.g = static_cast<uint32_t>(std::stoul(v[1]));
    result.x = static_cast<uint32_t>(std::stoul(v[2]));
    result.y = static_cast<uint32_t>(std::stoul(v[3]));

    if (result.p <= 255 || result.g <= 1 ||
        result.x <= 1 || result.x >= result.p - 1)
        throw std::runtime_error("Некорректный ключ Эль-Гамаля");

    return result;
}

std::string keyText(const ElGamalKey& key)
{
    return std::to_string(key.p) + " " +
           std::to_string(key.g) + " " +
           std::to_string(key.x) + " " +
           std::to_string(key.y);
}

std::vector<uint8_t> encryptData(const uint8_t* data, std::size_t size,
                                 const ElGamalKey& key)
{
    std::vector<uint8_t> result;
    result.reserve(size * 4);

    for (std::size_t i = 0; i < size; ++i)
    {
        // Для каждого байта используется новый случайный эфемерный k.
        uint32_t k = plugin_common::randomUInt(2, key.p - 2);
        uint32_t c1 = static_cast<uint32_t>(
            plugin_common::modPow(key.g, k, key.p));
        uint32_t s = static_cast<uint32_t>(
            plugin_common::modPow(key.y, k, key.p));
        uint32_t c2 = static_cast<uint32_t>(
            (static_cast<uint64_t>(data[i]) * s) % key.p);

        // c1 и c2 записываются по два байта big-endian.
        result.push_back(static_cast<uint8_t>((c1 >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(c1 & 0xFF));
        result.push_back(static_cast<uint8_t>((c2 >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(c2 & 0xFF));
    }

    return result;
}

std::vector<uint8_t> decryptData(const uint8_t* data, std::size_t size,
                                 const ElGamalKey& key)
{
    if (size % 4 != 0)
        throw std::runtime_error("Некорректный шифртекст Эль-Гамаля");

    std::vector<uint8_t> result;
    result.reserve(size / 4);

    for (std::size_t i = 0; i < size; i += 4)
    {
        uint32_t c1 = (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
        uint32_t c2 = (static_cast<uint32_t>(data[i + 2]) << 8) | data[i + 3];

        uint32_t s = static_cast<uint32_t>(
            plugin_common::modPow(c1, key.x, key.p));
        uint32_t inv = static_cast<uint32_t>(
            plugin_common::modInverse(s, key.p));
        uint32_t m = static_cast<uint32_t>(
            (static_cast<uint64_t>(c2) * inv) % key.p);

        if (m > 255)
            throw std::runtime_error("Ошибка дешифрования Эль-Гамаля");

        result.push_back(static_cast<uint8_t>(m));
    }

    return result;
}
}

extern "C"
{
PLUGIN_EXPORT void plugin_run()
{
    plugin_common::clearError();
}

PLUGIN_EXPORT const char* plugin_name()
{
    return "Эль-Гамаль";
}

PLUGIN_EXPORT const char* plugin_error()
{
    return plugin_common::error();
}

PLUGIN_EXPORT int plugin_generate_key(MutBuffer* key)
{
    try
    {
        plugin_common::clearError();
        return plugin_common::finishKey(keyText(generateKey()), key);
    }
    catch (const std::exception& e)
    {
        plugin_common::setError(e.what());
        return 1;
    }
}

PLUGIN_EXPORT int plugin_encrypt(const ConstBuffer* data,
                                 const ConstBuffer* key,
                                 MutBuffer* out)
{
    try
    {
        plugin_common::clearError();
        if (!data || !key || !out)
            throw std::runtime_error("Пустые данные или ключ Эль-Гамаля");

        ElGamalKey value = readKey(key->data, key->size);
        return plugin_common::finish(
            encryptData(data->data, data->size, value), out);
    }
    catch (const std::exception& e)
    {
        plugin_common::setError(e.what());
        return 1;
    }
}

PLUGIN_EXPORT int plugin_decrypt(const ConstBuffer* data,
                                 const ConstBuffer* key,
                                 MutBuffer* out)
{
    try
    {
        plugin_common::clearError();
        if (!data || !key || !out)
            throw std::runtime_error("Пустые данные или ключ Эль-Гамаля");

        ElGamalKey value = readKey(key->data, key->size);
        return plugin_common::finish(
            decryptData(data->data, data->size, value), out);
    }
    catch (const std::exception& e)
    {
        plugin_common::setError(e.what());
        return 1;
    }
}

PLUGIN_EXPORT void plugin_free(MutBuffer* buffer)
{
    if (buffer)
    {
        delete[] buffer->data;
        buffer->data = nullptr;
        buffer->size = 0;
    }
}
}
