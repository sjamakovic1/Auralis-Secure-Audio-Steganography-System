#include "stegowav/crypto/prime/MillerRabin.hpp"

#include "stegowav/crypto/random/SecureRandom.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace stegowav::crypto::prime {
namespace {

using bigint::BigInteger;

BigInteger randomBelow(const BigInteger& limit)
{
    if (limit.isZero()) {
        throw std::invalid_argument("Random range limit must be positive.");
    }

    const BigInteger maximum = limit - BigInteger{1};
    const std::size_t bitLength = maximum.bitLength();
    if (bitLength == 0) {
        return BigInteger{};
    }

    const std::size_t byteCount = bitLength / 8U + (bitLength % 8U != 0 ? 1U : 0U);
    const std::size_t excessBits = byteCount * 8U - bitLength;

    while (true) {
        auto bytes = random::SecureRandom::bytes(byteCount);
        if (excessBits != 0) {
            const auto mask = static_cast<std::uint8_t>(0xFFU >> excessBits);
            bytes[0] &= static_cast<std::byte>(mask);
        }

        BigInteger candidate = BigInteger::fromBytes(bytes);
        if (candidate < limit) {
            return candidate;
        }
    }
}

} // namespace

bool MillerRabin::isProbablePrime(const BigInteger& n, std::size_t rounds)
{
    if (rounds == 0) {
        throw std::invalid_argument("Miller-Rabin requires at least one round.");
    }

    const BigInteger two{2};
    const BigInteger three{3};
    if (n < two) {
        return false;
    }
    if (n == two || n == three) {
        return true;
    }
    if (!n.isOdd()) {
        return false;
    }

    const BigInteger nMinusOne = n - BigInteger{1};
    BigInteger d = nMinusOne;
    std::size_t s = 0;
    while (!d.isOdd()) {
        d = d >> 1U;
        ++s;
    }

    const BigInteger baseRangeSize = n - BigInteger{3};
    for (std::size_t round = 0; round < rounds; ++round) {
        const BigInteger base = randomBelow(baseRangeSize) + two;
        BigInteger x = BigInteger::modPow(base, d, n);

        if (x == BigInteger{1} || x == nMinusOne) {
            continue;
        }

        bool roundPassed = false;
        for (std::size_t iteration = 1; iteration < s; ++iteration) {
            x = (x * x) % n;
            if (x == nMinusOne) {
                roundPassed = true;
                break;
            }
        }
        if (!roundPassed) {
            return false;
        }
    }

    return true;
}

} // namespace stegowav::crypto::prime
