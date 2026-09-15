#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::padding {

class Pkcs7 {
public:
    [[nodiscard]] static std::vector<std::byte> pad(
        std::span<const std::byte> data, std::size_t blockSize);

    [[nodiscard]] static std::vector<std::byte> unpad(
        std::span<const std::byte> data, std::size_t blockSize);
};

} // namespace stegowav::crypto::padding
