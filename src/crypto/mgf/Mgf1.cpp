#include "stegowav/crypto/mgf/Mgf1.hpp"

#include "stegowav/crypto/hash/Sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace stegowav::crypto::mgf {
namespace {

std::array<std::byte, 4> counterBytes(std::uint32_t counter) noexcept
{
    return {
        static_cast<std::byte>((counter >> 24U) & 0xFFU),
        static_cast<std::byte>((counter >> 16U) & 0xFFU),
        static_cast<std::byte>((counter >> 8U) & 0xFFU),
        static_cast<std::byte>(counter & 0xFFU)
    };
}

} // namespace

std::vector<std::byte> Mgf1::generate(
    std::span<const std::byte> seed, std::size_t maskLength)
{
    if (maskLength == 0) {
        return {};
    }
    if (seed.size() > std::numeric_limits<std::size_t>::max() - 4U) {
        throw std::overflow_error("MGF1 seed is too large.");
    }

    const std::size_t digestSize = hash::Sha256::DigestSize;
    const std::size_t iterations = maskLength / digestSize
        + (maskLength % digestSize != 0 ? 1U : 0U);
    constexpr std::uint64_t MaxIterations =
        static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U;
    if (iterations > MaxIterations) {
        throw std::overflow_error("MGF1 mask length exceeds the 32-bit counter range.");
    }

    std::vector<std::byte> mask;
    mask.reserve(maskLength);

    std::vector<std::byte> hashInput;
    hashInput.reserve(seed.size() + 4U);

    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        hashInput.assign(seed.begin(), seed.end());
        const auto counter = counterBytes(static_cast<std::uint32_t>(iteration));
        hashInput.insert(hashInput.end(), counter.begin(), counter.end());

        const auto digest = hash::Sha256::digest(
            std::span<const std::byte>(hashInput));
        const std::size_t remaining = maskLength - mask.size();
        const std::size_t bytesToCopy = std::min(remaining, digest.size());
        mask.insert(
            mask.end(), digest.begin(),
            digest.begin() + static_cast<std::ptrdiff_t>(bytesToCopy));
    }

    return mask;
}

} // namespace stegowav::crypto::mgf
