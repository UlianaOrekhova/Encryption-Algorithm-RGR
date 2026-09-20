#ifndef PLUGIN_API_H
#define PLUGIN_API_H

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#define PLUGIN_EXPORT __declspec(dllexport)
#else
#define PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

// Единые типы обмена данными между менеджером и плагинами.
struct ConstBuffer
{
    const uint8_t* data;
    std::size_t size;
};

struct MutBuffer
{
    uint8_t* data;
    std::size_t size;
};

using PluginRun = void();
using PluginName = const char*();
using PluginError = const char*();
using PluginGenerateKey = int(MutBuffer* key);
using PluginTransform = int(const ConstBuffer* data,
                            const ConstBuffer* key,
                            MutBuffer* out);
using PluginFree = void(MutBuffer* buffer);

extern "C"
{
    PLUGIN_EXPORT void plugin_run();
    PLUGIN_EXPORT const char* plugin_name();
    PLUGIN_EXPORT const char* plugin_error();

    PLUGIN_EXPORT int plugin_generate_key(MutBuffer* key);

    PLUGIN_EXPORT int plugin_encrypt(const ConstBuffer* data,
                                     const ConstBuffer* key,
                                     MutBuffer* out);

    PLUGIN_EXPORT int plugin_decrypt(const ConstBuffer* data,
                                     const ConstBuffer* key,
                                     MutBuffer* out);

    PLUGIN_EXPORT void plugin_free(MutBuffer* buffer);
}

#endif
