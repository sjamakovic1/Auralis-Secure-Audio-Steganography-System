#pragma once

#include "stegowav/audio/PcmBuffer.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::steganography {

class LsbSteganography {
public:
    LsbSteganography() = default;
    ~LsbSteganography() = default;

    void embed(audio::PcmBuffer& pcm, std::span<const std::byte> data) const;

    [[nodiscard]] std::vector<std::byte> extract(
        const audio::PcmBuffer& pcm, std::size_t byteCount) const;

    [[nodiscard]] std::size_t capacityBytes(const audio::PcmBuffer& pcm) const noexcept;
};

} // namespace stegowav::steganography
