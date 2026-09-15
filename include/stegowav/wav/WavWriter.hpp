#pragma once

#include "stegowav/wav/WavFile.hpp"

#include <filesystem>

namespace stegowav::wav {

class WavWriter {
public:
    WavWriter() = default;
    ~WavWriter() = default;

    void write(const WavFile& wav, const std::filesystem::path& path) const;
};

} // namespace stegowav::wav
