#pragma once

#include "stegowav/wav/WavFile.hpp"

#include <filesystem>

namespace stegowav::wav {

class WavReader {
public:
    WavReader() = default;
    ~WavReader() = default;

    [[nodiscard]] WavFile read(const std::filesystem::path& path) const;
};

} // namespace stegowav::wav
