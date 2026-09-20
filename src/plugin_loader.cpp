#include "plugin_loader.h"

#include <filesystem>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

Plugin::Plugin()
    : handle_(nullptr), run_(nullptr), name_(nullptr), error_(nullptr),
      generateKey_(nullptr), encrypt_(nullptr), decrypt_(nullptr), free_(nullptr)
{
}

Plugin::~Plugin()
{
    unload();
}

Plugin::Plugin(Plugin&& other) noexcept
    : handle_(other.handle_), run_(other.run_), name_(other.name_),
      error_(other.error_), generateKey_(other.generateKey_),
      encrypt_(other.encrypt_), decrypt_(other.decrypt_), free_(other.free_),
      path_(std::move(other.path_))
{
    other.handle_ = nullptr;
    other.run_ = nullptr;
    other.name_ = nullptr;
    other.error_ = nullptr;
    other.generateKey_ = nullptr;
    other.encrypt_ = nullptr;
    other.decrypt_ = nullptr;
    other.free_ = nullptr;
}

Plugin& Plugin::operator=(Plugin&& other) noexcept
{
    if (this != &other)
    {
        unload();
        handle_ = other.handle_;
        run_ = other.run_;
        name_ = other.name_;
        error_ = other.error_;
        generateKey_ = other.generateKey_;
        encrypt_ = other.encrypt_;
        decrypt_ = other.decrypt_;
        free_ = other.free_;
        path_ = std::move(other.path_);

        other.handle_ = nullptr;
        other.run_ = nullptr;
        other.name_ = nullptr;
        other.error_ = nullptr;
        other.generateKey_ = nullptr;
        other.encrypt_ = nullptr;
        other.decrypt_ = nullptr;
        other.free_ = nullptr;
    }
    return *this;
}

void Plugin::load(const std::filesystem::path& path)
{
    unload();
    path_ = path;

#ifdef _WIN32
    handle_ = reinterpret_cast<void*>(LoadLibraryW(path.c_str()));
    if (!handle_)
        throw std::runtime_error("Ошибка загрузки библиотеки: " + path.u8string());

    auto get = [&](const char* name) -> FARPROC {
        return GetProcAddress(reinterpret_cast<HMODULE>(handle_), name);
    };
#else
    handle_ = dlopen(path.c_str(), RTLD_NOW);
    if (!handle_)
        throw std::runtime_error(std::string("Ошибка загрузки библиотеки: ") + dlerror());

    auto get = [&](const char* name) -> void* {
        return dlsym(handle_, name);
    };
#endif

    run_ = reinterpret_cast<PluginRun*>(get("plugin_run"));
    name_ = reinterpret_cast<PluginName*>(get("plugin_name"));
    error_ = reinterpret_cast<PluginError*>(get("plugin_error"));
    generateKey_ = reinterpret_cast<PluginGenerateKey*>(get("plugin_generate_key"));
    encrypt_ = reinterpret_cast<PluginTransform*>(get("plugin_encrypt"));
    decrypt_ = reinterpret_cast<PluginTransform*>(get("plugin_decrypt"));
    free_ = reinterpret_cast<PluginFree*>(get("plugin_free"));

    if (!run_ || !name_ || !error_ || !generateKey_ ||
        !encrypt_ || !decrypt_ || !free_)
    {
        unload();
        throw std::runtime_error("Функции единого plugin API не найдены в " + path.u8string());
    }

    run_();
}

void Plugin::unload()
{
    if (!handle_)
        return;

#ifdef _WIN32
    FreeLibrary(reinterpret_cast<HMODULE>(handle_));
#else
    dlclose(handle_);
#endif

    handle_ = nullptr;
    run_ = nullptr;
    name_ = nullptr;
    error_ = nullptr;
    generateKey_ = nullptr;
    encrypt_ = nullptr;
    decrypt_ = nullptr;
    free_ = nullptr;
}

bool Plugin::isLoaded() const
{
    return handle_ != nullptr;
}

std::string Plugin::name() const
{
    if (!name_)
        return {};
    return name_();
}

std::string Plugin::error() const
{
    if (!error_)
        return "Неизвестная ошибка плагина";
    return error_();
}

std::vector<uint8_t> Plugin::generateKey() const
{
    if (!isLoaded())
        throw std::runtime_error("Плагин не загружен");

    MutBuffer buffer{nullptr, 0};

    if (generateKey_(&buffer) != 0)
        throw std::runtime_error(error());

    std::vector<uint8_t> result(buffer.data, buffer.data + buffer.size);
    free_(&buffer);
    return result;
}

static std::vector<uint8_t> transform(PluginTransform* function,
                                      PluginFree* free_function,
                                      PluginError* error_function,
                                      const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& key)
{
    ConstBuffer input{data.data(), data.size()};
    ConstBuffer key_buffer{key.data(), key.size()};
    MutBuffer output{nullptr, 0};

    if (function(&input, &key_buffer, &output) != 0)
        throw std::runtime_error(error_function());

    std::vector<uint8_t> result(output.data, output.data + output.size);
    free_function(&output);
    return result;
}

std::vector<uint8_t> Plugin::encrypt(const std::vector<uint8_t>& data,
                                     const std::vector<uint8_t>& key) const
{
    if (!isLoaded())
        throw std::runtime_error("Плагин не загружен");
    return transform(encrypt_, free_, error_, data, key);
}

std::vector<uint8_t> Plugin::decrypt(const std::vector<uint8_t>& data,
                                     const std::vector<uint8_t>& key) const
{
    if (!isLoaded())
        throw std::runtime_error("Плагин не загружен");
    return transform(decrypt_, free_, error_, data, key);
}

std::vector<LoadedPlugin> loadPlugins(const std::filesystem::path& baseDir)
{
    const std::filesystem::path root =
        baseDir.empty() ? std::filesystem::current_path() : baseDir;

    std::vector<LoadedPlugin> plugins;

#ifdef _WIN32
    const std::filesystem::path rsa = root / "plugins" / "rsa.dll";
    const std::filesystem::path elgamal = root / "plugins" / "elgamal.dll";
    const std::filesystem::path wake = root / "plugins" / "wake.dll";
#else
    const std::filesystem::path rsa = root / "plugins" / "librsa.so";
    const std::filesystem::path elgamal = root / "plugins" / "libelgamal.so";
    const std::filesystem::path wake = root / "plugins" / "libwake.so";
#endif

    plugins.push_back({"rsa", rsa.u8string(), {}});
    plugins.push_back({"elgamal", elgamal.u8string(), {}});
    plugins.push_back({"wake", wake.u8string(), {}});

    for (auto& item : plugins)
    {
        item.plugin.load(std::filesystem::u8path(item.file));
    }

    return plugins;
}
