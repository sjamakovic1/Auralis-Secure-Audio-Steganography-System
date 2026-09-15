#pragma once

#include "stegowav/crypto/bigint/BigInteger.hpp"
#include "stegowav/crypto/rsa/RsaKeyPair.hpp"

#include <cstddef>

namespace stegowav::crypto::rsa {

class RsaKeyGenerator {
public:
    [[nodiscard]] static RsaKeyPair generate(
        std::size_t modulusBits,
        const bigint::BigInteger& publicExponent,
        std::size_t millerRabinRounds = 40);
};

} // namespace stegowav::crypto::rsa
