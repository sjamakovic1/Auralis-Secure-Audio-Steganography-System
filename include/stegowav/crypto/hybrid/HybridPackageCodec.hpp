#pragma once

#include "stegowav/crypto/hybrid/HybridCipher.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::hybrid {

class HybridPackageCodec {
public:
    static constexpr std::byte Version{0x01};
    static constexpr std::size_t HeaderSize = 25;

    [[nodiscard]] static std::vector<std::byte> encode(
        const HybridEncryptedData& data);

    [[nodiscard]] static HybridEncryptedData decode(
        std::span<const std::byte> encoded);
};

} // namespace stegowav::crypto::hybrid
