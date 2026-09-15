#include "stegowav/crypto/hash/Sha256.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace stegowav::crypto::hash {
namespace {

constexpr std::array<std::uint32_t, 8> InitialHash{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

constexpr std::array<std::uint32_t, 64> RoundConstants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

constexpr std::uint32_t choose(
    std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
{
    return (x & y) ^ (~x & z);
}

constexpr std::uint32_t majority(
    std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
{
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t bigSigma0(std::uint32_t value) noexcept
{
    return std::rotr(value, 2) ^ std::rotr(value, 13) ^ std::rotr(value, 22);
}

constexpr std::uint32_t bigSigma1(std::uint32_t value) noexcept
{
    return std::rotr(value, 6) ^ std::rotr(value, 11) ^ std::rotr(value, 25);
}

constexpr std::uint32_t smallSigma0(std::uint32_t value) noexcept
{
    return std::rotr(value, 7) ^ std::rotr(value, 18) ^ (value >> 3U);
}

constexpr std::uint32_t smallSigma1(std::uint32_t value) noexcept
{
    return std::rotr(value, 17) ^ std::rotr(value, 19) ^ (value >> 10U);
}

std::uint32_t readUint32BE(const std::byte* bytes) noexcept
{
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[0])) << 24U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 8U)
        | static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3]));
}

void writeUint32BE(
    std::array<std::byte, Sha256::DigestSize>& output,
    std::size_t offset,
    std::uint32_t value) noexcept
{
    output[offset] = static_cast<std::byte>((value >> 24U) & 0xFFU);
    output[offset + 1U] = static_cast<std::byte>((value >> 16U) & 0xFFU);
    output[offset + 2U] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    output[offset + 3U] = static_cast<std::byte>(value & 0xFFU);
}

std::vector<std::byte> padMessage(std::span<const std::byte> data)
{
    if (data.size() > std::numeric_limits<std::uint64_t>::max() / 8U) {
        throw std::overflow_error("SHA-256 input is too large for the 64-bit length field.");
    }

    const std::uint64_t bitLength = static_cast<std::uint64_t>(data.size()) * 8U;
    std::vector<std::byte> padded(data.begin(), data.end());
    padded.push_back(std::byte{0x80});

    while (padded.size() % Sha256::BlockSize != 56U) {
        padded.push_back(std::byte{0});
    }

    for (int shift = 56; shift >= 0; shift -= 8) {
        padded.push_back(static_cast<std::byte>((bitLength >> shift) & 0xFFU));
    }
    return padded;
}

} // namespace

std::array<std::byte, Sha256::DigestSize> Sha256::digest(
    std::span<const std::byte> data)
{
    const std::vector<std::byte> padded = padMessage(data);
    std::array<std::uint32_t, 8> hash = InitialHash;

    for (std::size_t blockOffset = 0;
         blockOffset < padded.size();
         blockOffset += BlockSize) {
        std::array<std::uint32_t, 64> words{};
        for (std::size_t index = 0; index < 16; ++index) {
            words[index] = readUint32BE(padded.data() + blockOffset + index * 4U);
        }
        for (std::size_t index = 16; index < words.size(); ++index) {
            words[index] = smallSigma1(words[index - 2U])
                + words[index - 7U]
                + smallSigma0(words[index - 15U])
                + words[index - 16U];
        }

        std::uint32_t a = hash[0];
        std::uint32_t b = hash[1];
        std::uint32_t c = hash[2];
        std::uint32_t d = hash[3];
        std::uint32_t e = hash[4];
        std::uint32_t f = hash[5];
        std::uint32_t g = hash[6];
        std::uint32_t h = hash[7];

        for (std::size_t round = 0; round < 64; ++round) {
            const std::uint32_t temporary1 = h + bigSigma1(e) + choose(e, f, g)
                + RoundConstants[round] + words[round];
            const std::uint32_t temporary2 = bigSigma0(a) + majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    std::array<std::byte, DigestSize> result{};
    for (std::size_t index = 0; index < hash.size(); ++index) {
        writeUint32BE(result, index * 4U, hash[index]);
    }
    return result;
}

} // namespace stegowav::crypto::hash
