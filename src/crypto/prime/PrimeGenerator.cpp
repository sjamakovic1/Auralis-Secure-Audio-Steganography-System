#include "stegowav/crypto/prime/PrimeGenerator.hpp"

#include "stegowav/crypto/prime/MillerRabin.hpp"
#include "stegowav/crypto/random/SecureRandom.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace stegowav::crypto::prime {
namespace {

using bigint::BigInteger;

constexpr std::array<std::uint16_t, 167> SmallPrimes{
    3,5,7,11,13,17,19,23,29,31,
    37,41,43,47,53,59,61,67,71,73,79,83,89,97,
    101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,
    181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,
    271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,
    373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,
    463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,
    577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,
    673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,
    787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,
    887,907,911,919,929,937,941,947,953,967,971,977,983,991,997
};

enum class SmallPrimeScreeningResult {
    Prime,
    Composite,
    Undetermined
};

SmallPrimeScreeningResult screenSmallPrimes(const BigInteger& candidate)
{
    for (const std::uint16_t prime : SmallPrimes) {
        if (candidate == BigInteger{prime}) {
            return SmallPrimeScreeningResult::Prime;
        }
        if (candidate.moduloSmall(prime) == 0) {
            return SmallPrimeScreeningResult::Composite;
        }
    }
    return SmallPrimeScreeningResult::Undetermined;
}

BigInteger randomOddCandidate(std::size_t bitLength)
{
    const std::size_t byteCount = bitLength / 8U + (bitLength % 8U != 0 ? 1U : 0U);
    auto bytes = random::SecureRandom::bytes(byteCount);

    const std::size_t significantBits = bitLength % 8U;
    if (significantBits == 0) {
        bytes[0] |= std::byte{0x80};
    } else {
        const auto mask = static_cast<std::uint8_t>((std::uint16_t{1} << significantBits) - 1U);
        const auto topBit = static_cast<std::uint8_t>(
            std::uint16_t{1} << (significantBits - 1U));
        bytes[0] &= static_cast<std::byte>(mask);
        bytes[0] |= static_cast<std::byte>(topBit);
    }

    bytes.back() |= std::byte{1};
    return BigInteger::fromBytes(bytes);
}

} // namespace

BigInteger PrimeGenerator::generate(
    std::size_t bitLength, std::size_t millerRabinRounds)
{
    if (bitLength < 2) {
        throw std::invalid_argument("Prime bit length must be at least two.");
    }
    if (millerRabinRounds == 0) {
        throw std::invalid_argument("Miller-Rabin requires at least one round.");
    }

    const BigInteger two{2};
    while (true) {
        BigInteger candidate = randomOddCandidate(bitLength);

        while (candidate.bitLength() == bitLength) {
            const SmallPrimeScreeningResult screening = screenSmallPrimes(candidate);
            if (screening == SmallPrimeScreeningResult::Prime) {
                return candidate;
            }
            if (screening == SmallPrimeScreeningResult::Undetermined
                && MillerRabin::isProbablePrime(candidate, millerRabinRounds)) {
                return candidate;
            }
            candidate += two;
        }
    }
}

} // namespace stegowav::crypto::prime
