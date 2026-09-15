#pragma once

#include <array>
#include <cstddef>
#include <span>

namespace stegowav::crypto::hash {

class Sha256 {
public:
    static constexpr std::size_t DigestSize = 32;
    static constexpr std::size_t BlockSize = 64;

    [[nodiscard]] static std::array<std::byte, DigestSize> digest(
        std::span<const std::byte> data);
};

} // namespace stegowav::crypto::hash
