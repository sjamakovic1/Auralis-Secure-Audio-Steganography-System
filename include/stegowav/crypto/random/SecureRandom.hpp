#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::random {

class SecureRandom {
public:
    [[nodiscard]] static std::vector<std::byte> bytes(std::size_t count);
    static void fill(std::span<std::byte> buffer);
};

} // namespace stegowav::crypto::random
