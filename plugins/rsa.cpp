#include "plugin_common.h"

#include <stdexcept>

namespace
{
struct RSAKey
{
    uint32_t p = 0;
    uint32_t q = 0;
    uint32_t n = 0;
    uint32_t e = 0;
    uint32_t d = 0;
};

bool isPrime(uint32_t n)
{
    if (n < 2)
        return false;
    if (n % 2 == 0)
        return n == 2;

    for (uint32_t d = 3; d * d <= n; d += 2)
        if (n % d == 0)
            return false;

    return true;
}

RSAKey generateKey()
{
    RSAKey key;

    do
    {
        key.p = plugin_common::randomUInt(211, 251);
        if (key.p % 2 == 0)
            --key.p;
        while (!isPrime(key.p))
            key.p -= 2;

        key.q = plugin_common::randomUInt(211, 251);
        if (key.q % 2 == 0)
            --key.q;
        while (!isPrime(key.q))
            key.q -= 2;
    }
    while (key.p == key.q);

    key.n = key.p * key.q;
    uint64_t phi = static_cast<uint64_t>(key.p - 1) * (key.q - 1);

    key.e = 17;
    if (plugin_common::gcdInt(key.e, static_cast<int64_t>(phi)) != 1)
    {
        key.e = 3;
        while (plugin_common::gcdInt(key.e, static_cast<int64_t>(phi)) != 1)
            key.e += 2;
    }

    key.d = static_cast<uint32_t>(plugin_common::modInverse(key.e, static_cast<int64_t>(phi)));
    return key;
}

RSAKey readKey(const uint8_t* key, std::size_t key_size)
{
    std::string text(reinterpret_cast<const char*>(key), key_size);
    std::vector<std::string> v = plugin_common::split(text);

    if (v.size() != 5)
        throw std::runtime_error("Неверный формат ключа RSA");

    for (const std::string& value : v)
        if (!plugin_common::isNumber(value))
            throw std::runtime_error("Неверный формат ключа RSA");

    RSAKey result;
    result.p = static_cast<uint32_t>(std::stoul(v[0]));
    result.q = static_cast<uint32_t>(std::stoul(v[1]));
    result.n = static_cast<uint32_t>(std::stoul(v[2]));
    result.e = static_cast<uint32_t>(std::stoul(v[3]));
    result.d = static_cast<uint32_t>(std::stoul(v[4]));

    if (!isPrime(result.p) || !isPrime(result.q) ||
        result.n != result.p * result.q || result.n <= 255)
        throw std::runtime_error("Некорректный ключ RSA");

    return result;
}

std::string keyText(const RSAKey& key)
{
    return std::to_string(key.p) + " " +
           std::to_string(key.q) + " " +
           std::to_string(key.n) + " " +
           std::to_string(key.e) + " " +
           std::to_string(key.d);
}

std::vector<uint8_t> encryptData(const uint8_t* data, std::size_t size,
                                 const RSAKey& key)
{
    if (key.n > 65535)
        throw std::runtime_error("Для учебного RSA n должен быть не больше 65535");

    std::vector<uint8_t> result;
    result.reserve(size * 2);

    for (std::size_t i = 0; i < size; ++i)
    {
        uint32_t c = static_cast<uint32_t>(
            plugin_common::modPow(data[i], key.e, key.n));

        // Как в контрольном примере отчёта: один байт -> два байта big-endian.
        result.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(c & 0xFF));
    }

    return result;
}

std::vector<uint8_t> decryptData(const uint8_t* data, std::size_t size,
                                 const RSAKey& key)
{
    if (size % 2 != 0)
        throw std::runtime_error("Некорректный RSA-шифртекст");

    std::vector<uint8_t> result;
    result.reserve(size / 2);

    for (std::size_t i = 0; i < size; i += 2)
    {
        uint32_t c = (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
        uint32_t m = static_cast<uint32_t>(
            plugin_common::modPow(c, key.d, key.n));

        if (m > 255)
            throw std::runtime_error("Ошибка RSA-дешифрования");

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
    return "RSA";
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
        RSAKey value = generateKey();
        return plugin_common::finishKey(keyText(value), key);
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
            throw std::runtime_error("Пустые данные или ключ RSA");

        RSAKey value = readKey(key->data, key->size);
        return plugin_common::finish(encryptData(data->data, data->size, value), out);
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
            throw std::runtime_error("Пустые данные или ключ RSA");

        RSAKey value = readKey(key->data, key->size);
        return plugin_common::finish(decryptData(data->data, data->size, value), out);
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
