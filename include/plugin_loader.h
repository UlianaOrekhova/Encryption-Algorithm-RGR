#ifndef PLUGIN_LOADER_H
#define PLUGIN_LOADER_H

#include "plugin_api.h"
#include <filesystem>
#include <string>
#include <vector>

class Plugin
{
public:
    Plugin();
    ~Plugin();
    Plugin(const Plugin&) = delete;
    Plugin& operator=(const Plugin&) = delete;
    Plugin(Plugin&& other) noexcept;
    Plugin& operator=(Plugin&& other) noexcept;

    void load(const std::filesystem::path& path);
    void unload();
    bool isLoaded() const;

    std::string name() const;
    std::string error() const;

    std::vector<uint8_t> generateKey() const;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& key) const;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& key) const;

private:
    void* handle_;
    PluginRun* run_;
    PluginName* name_;
    PluginError* error_;
    PluginGenerateKey* generateKey_;
    PluginTransform* encrypt_;
    PluginTransform* decrypt_;
    PluginFree* free_;
    std::filesystem::path path_;
};

struct LoadedPlugin
{
    std::string id;
    std::string file;
    Plugin plugin;
};

std::vector<LoadedPlugin> loadPlugins(const std::filesystem::path& baseDir = {});

#endif
