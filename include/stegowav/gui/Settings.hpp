#pragma once

#include <filesystem>
#include <string>

namespace stegowav::gui {

struct Settings {
    std::wstring lastPublicKey;
    std::wstring lastPrivateKey;
    std::wstring lastInputWavDirectory;
    std::wstring lastOutputWavDirectory;
    std::wstring rsaBits{L"2048"};
    std::wstring publicExponent{L"65537"};

    static Settings load(const std::filesystem::path& path);
    void save(const std::filesystem::path& path) const;
};

std::filesystem::path executableDirectory();

} // namespace stegowav::gui
