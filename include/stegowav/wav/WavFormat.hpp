#pragma once

#include <cstdint>

namespace stegowav::wav {

struct WavFormat {
    std::uint16_t audioFormat{};
    std::uint16_t numChannels{};
    std::uint32_t sampleRate{};
    std::uint32_t byteRate{};
    std::uint16_t blockAlign{};
    std::uint16_t bitsPerSample{};
};

} // namespace stegowav::wav
