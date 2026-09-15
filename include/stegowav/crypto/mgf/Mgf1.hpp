#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::mgf {

class Mgf1 {
public:
    [[nodiscard]] static std::vector<std::byte> generate(
        std::span<const std::byte> seed, std::size_t maskLength);
};

} // namespace stegowav::crypto::mgf
