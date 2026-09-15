#include "stegowav/gui/Settings.hpp"

#include <windows.h>

#include <array>
#include <stdexcept>

namespace stegowav::gui {
namespace {

std::wstring readValue(const std::filesystem::path& path, const wchar_t* key,
                       const wchar_t* fallback = L"")
{
    std::array<wchar_t, 32768> value{};
    GetPrivateProfileStringW(L"Auralis", key, fallback, value.data(),
                             static_cast<DWORD>(value.size()), path.c_str());
    return value.data();
}

void writeValue(const std::filesystem::path& path, const wchar_t* key,
                const std::wstring& value)
{
    WritePrivateProfileStringW(L"Auralis", key, value.c_str(), path.c_str());
}

} // namespace

std::filesystem::path executableDirectory()
{
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(nullptr, path.data(),
                                            static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) {
        throw std::runtime_error("Could not determine executable directory.");
    }
    return std::filesystem::path(std::wstring(path.data(), length)).parent_path();
}

Settings Settings::load(const std::filesystem::path& path)
{
    Settings settings;
    settings.lastPublicKey = readValue(path, L"lastPublicKey");
    settings.lastPrivateKey = readValue(path, L"lastPrivateKey");
    settings.lastInputWavDirectory = readValue(path, L"lastInputWavDirectory");
    settings.lastOutputWavDirectory = readValue(path, L"lastOutputWavDirectory");
    settings.rsaBits = readValue(path, L"rsaBits", L"2048");
    settings.publicExponent = readValue(path, L"publicExponent", L"65537");
    return settings;
}

void Settings::save(const std::filesystem::path& path) const
{
    writeValue(path, L"lastPublicKey", lastPublicKey);
    writeValue(path, L"lastPrivateKey", lastPrivateKey);
    writeValue(path, L"lastInputWavDirectory", lastInputWavDirectory);
    writeValue(path, L"lastOutputWavDirectory", lastOutputWavDirectory);
    writeValue(path, L"rsaBits", rsaBits);
    writeValue(path, L"publicExponent", publicExponent);
}

} // namespace stegowav::gui
