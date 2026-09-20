#include "plugin_common.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace
{
const uint32_t TT[8] =
{
    0x726a8f3bU,
    0xe69a3b5cU,
    0xd3c71fe5U,
    0xab3c73d2U,
    0x4d3a8eb3U,
    0x0396d6e8U,
    0x3d4c2f7aU,
    0x9ee27cf3U
};

struct WAKEKey
{
    uint32_t k[4]{};
};

uint32_t bytesToWord(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void wordToBytes(uint32_t x, uint8_t* p)
{
    p[0] = static_cast<uint8_t>(x & 0xFF);
    p[1] = static_cast<uint8_t>((x >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((x >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((x >> 24) & 0xFF);
}

WAKEKey readKey(const uint8_t* key, std::size_t key_size)
{
    std::string text(reinterpret_cast<const char*>(key), key_size);
    std::vector<uint8_t> bytes = plugin_common::hexToBytes(text);

    if (bytes.size() != 16)
        throw std::runtime_error("Ключ WAKE должен содержать 16 байт");

    WAKEKey result;
    for (int i = 0; i < 4; ++i)
        result.k[i] = bytesToWord(bytes.data() + i * 4);

    return result;
}

std::string keyText(const WAKEKey& key)
{
    std::vector<uint8_t> bytes(16);
    for (int i = 0; i < 4; ++i)
        wordToBytes(key.k[i], bytes.data() + i * 4);
    return plugin_common::bytesToHex(bytes);
}

WAKEKey generateKey()
{
    WAKEKey key;
    for (uint32_t& value : key.k)
        value = plugin_common::random32();
    return key;
}

std::vector<uint32_t> makeTable(const WAKEKey& key)
{
    std::vector<uint32_t> t(257);

    t[0] = key.k[0];
    t[1] = key.k[1];
    t[2] = key.k[2];
    t[3] = key.k[3];

    // Заполнение таблицы.
    for (int p = 4; p < 256; ++p)
    {
        uint32_t x = t[p - 4] + t[p - 1];
        t[p] = (x >> 3) ^ TT[x & 7];
    }

    // Перемешивание начальных элементов.
    for (int p = 0; p < 23; ++p)
        t[p] += t[p + 89];

    // Формирование старшего байта как перестановки.
    uint32_t x = t[33];
    uint32_t z = (t[59] | 0x01000001U) & 0xff7fffffU;

    for (int p = 0; p < 256; ++p)
    {
        x = (x & 0xff7fffffU) + z;
        t[p] = (t[p] & 0x00ffffffU) ^ x;
    }

    // Финальное перемешивание.
    t[256] = t[0];
    x &= 0xffU;

    for (int p = 0; p < 256; ++p)
    {
        x = (t[p ^ x] ^ x) & 0xffU;
        t[p] = t[x];
        t[x] = t[p + 1];
    }

    return t;
}

uint32_t mix(uint32_t x, uint32_t y, const std::vector<uint32_t>& t)
{
    uint32_t sum = x + y;
    return ((sum >> 8) & 0x00ffffffU) ^ t[sum & 0xffU];
}

std::vector<uint32_t> process(const std::vector<uint32_t>& input,
                              const WAKEKey& key,
                              const std::vector<uint32_t>& t,
                              bool decrypt)
{
    std::vector<uint32_t> output = input;

    uint32_t r3 = key.k[0];
    uint32_t r4 = key.k[1];
    uint32_t r5 = key.k[2];
    uint32_t r6 = key.k[3];

    for (std::size_t i = 0; i < output.size(); ++i)
    {
        uint32_t r1 = output[i];
        uint32_t r2 = r1 ^ r6;
        output[i] = r2;

        // При дешифровании в первый M подставляется R1, а не R2.
        r3 = mix(r3, decrypt ? r1 : r2, t);
        r4 = mix(r4, r3, t);
        r5 = mix(r5, r4, t);
        r6 = mix(r6, r5, t);
    }

    return output;
}

std::vector<uint8_t> encryptData(const uint8_t* data, std::size_t size,
                                 const WAKEKey& key)
{
    // Добавляем длину, чтобы после выравнивания восстановить исходный размер.
    if (size > 0xFFFFFFFFULL - 4)
        throw std::runtime_error("Слишком большой файл для учебной реализации WAKE");

    std::vector<uint8_t> prepared(4 + size);
    wordToBytes(static_cast<uint32_t>(size), prepared.data());
    if (size != 0)
        std::memcpy(prepared.data() + 4, data, size);

    while (prepared.size() % 4 != 0)
        prepared.push_back(0);

    std::vector<uint32_t> words(prepared.size() / 4);
    for (std::size_t i = 0; i < words.size(); ++i)
        words[i] = bytesToWord(prepared.data() + i * 4);

    std::vector<uint32_t> t = makeTable(key);
    words = process(words, key, t, false);

    std::vector<uint8_t> result(words.size() * 4);
    for (std::size_t i = 0; i < words.size(); ++i)
        wordToBytes(words[i], result.data() + i * 4);

    return result;
}

std::vector<uint8_t> decryptData(const uint8_t* data, std::size_t size,
                                 const WAKEKey& key)
{
    if (size < 4 || size % 4 != 0)
        throw std::runtime_error("Некорректный шифртекст WAKE");

    std::vector<uint32_t> words(size / 4);
    for (std::size_t i = 0; i < words.size(); ++i)
        words[i] = bytesToWord(data + i * 4);

    std::vector<uint32_t> t = makeTable(key);
    words = process(words, key, t, true);

    std::vector<uint8_t> prepared(words.size() * 4);
    for (std::size_t i = 0; i < words.size(); ++i)
        wordToBytes(words[i], prepared.data() + i * 4);

    uint32_t originalSize = bytesToWord(prepared.data());
    if (originalSize > prepared.size() - 4)
        throw std::runtime_error("Ошибка WAKE: неверная длина данных");

    return std::vector<uint8_t>(prepared.begin() + 4,
                                prepared.begin() + 4 + originalSize);
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
    return "WAKE";
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
        if (!key || !out || (!data && data->size != 0))
            throw std::runtime_error("Пустые данные или ключ WAKE");

        WAKEKey value = readKey(key->data, key->size);
        return plugin_common::finish(
            encryptData(data ? data->data : nullptr, data ? data->size : 0, value), out);
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
        if (!key || !out || (!data && data->size != 0))
            throw std::runtime_error("Пустые данные или ключ WAKE");

        WAKEKey value = readKey(key->data, key->size);
        return plugin_common::finish(
            decryptData(data ? data->data : nullptr, data ? data->size : 0, value), out);
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
