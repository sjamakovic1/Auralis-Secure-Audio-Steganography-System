#pragma once

#include "stegowav/crypto/bigint/BigInteger.hpp"

#include <cstddef>

namespace stegowav::crypto::prime {

class MillerRabin {
public:
    [[nodiscard]] static bool isProbablePrime(
        const bigint::BigInteger& n, std::size_t rounds);
};

} // namespace stegowav::crypto::prime
