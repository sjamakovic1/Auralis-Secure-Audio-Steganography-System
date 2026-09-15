#pragma once

#include "stegowav/crypto/bigint/BigInteger.hpp"

#include <cstddef>

namespace stegowav::crypto::prime {

class PrimeGenerator {
public:
    [[nodiscard]] static bigint::BigInteger generate(
        std::size_t bitLength, std::size_t millerRabinRounds = 40);
};

} // namespace stegowav::crypto::prime
