#pragma once

#include "stegowav/crypto/bigint/BigInteger.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::rsa {

class RsaConversion {
public:
    [[nodiscard]] static bigint::BigInteger os2ip(
        std::span<const std::byte> octets);

    [[nodiscard]] static std::vector<std::byte> i2osp(
        const bigint::BigInteger& value, std::size_t length);

    [[nodiscard]] static std::size_t modulusByteLength(
        const bigint::BigInteger& modulus);
};

} // namespace stegowav::crypto::rsa
