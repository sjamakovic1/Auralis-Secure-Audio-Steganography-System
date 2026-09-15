#include "stegowav/crypto/hybrid/HybridPackageCodec.hpp"

#include "stegowav/crypto/aes/Aes256.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace stegowav::crypto::hybrid {
namespace {

void appendUint32LittleEndian(
    std::vector<std::byte>& output, std::uint32_t value)
{
    output.push_back(static_cast<std::byte>(value & 0xFFU));
    output.push_back(static_cast<std::byte>((value >> 8U) & 0xFFU));
    output.push_back(static_cast<std::byte>((value >> 16U) & 0xFFU));
    output.push_back(static_cast<std::byte>((value >> 24U) & 0xFFU));
}

std::uint32_t readUint32LittleEndian(std::span<const std::byte> bytes) noexcept
{
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[0]))
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 8U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3])) << 24U);
}

[[noreturn]] void invalidPackage()
{
    throw std::runtime_error("Invalid hybrid package.");
}

std::size_t checkedTotalSize(std::size_t encryptedKeyLength, std::size_t ciphertextLength)
{
    constexpr std::size_t maximum = std::numeric_limits<std::size_t>::max();
    if (encryptedKeyLength > maximum - HybridPackageCodec::HeaderSize) {
        throw std::length_error("Hybrid package size is too large.");
    }
    const std::size_t headerAndKey =
        HybridPackageCodec::HeaderSize + encryptedKeyLength;
    if (ciphertextLength > maximum - headerAndKey) {
        throw std::length_error("Hybrid package size is too large.");
    }
    return headerAndKey + ciphertextLength;
}

} // namespace

std::vector<std::byte> HybridPackageCodec::encode(
    const HybridEncryptedData& data)
{
    if (data.encryptedSessionKey.empty()) {
        throw std::invalid_argument("Encrypted session key must not be empty.");
    }
    if (data.ciphertext.empty()
        || data.ciphertext.size() % aes::Aes256::BlockSize != 0) {
        throw std::invalid_argument(
            "Hybrid ciphertext must be non-empty and AES block-aligned.");
    }
    if (data.encryptedSessionKey.size()
        > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("Encrypted session key is too large to serialize.");
    }
    if (data.ciphertext.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("Ciphertext is too large to serialize.");
    }

    const std::size_t totalSize = checkedTotalSize(
        data.encryptedSessionKey.size(), data.ciphertext.size());
    std::vector<std::byte> encoded;
    encoded.reserve(totalSize);

    encoded.push_back(Version);
    appendUint32LittleEndian(
        encoded, static_cast<std::uint32_t>(data.encryptedSessionKey.size()));
    appendUint32LittleEndian(
        encoded, static_cast<std::uint32_t>(data.ciphertext.size()));
    encoded.insert(encoded.end(), data.iv.begin(), data.iv.end());
    encoded.insert(
        encoded.end(), data.encryptedSessionKey.begin(), data.encryptedSessionKey.end());
    encoded.insert(encoded.end(), data.ciphertext.begin(), data.ciphertext.end());
    return encoded;
}

HybridEncryptedData HybridPackageCodec::decode(
    std::span<const std::byte> encoded)
{
    if (encoded.size() < HeaderSize) {
        invalidPackage();
    }
    if (encoded[0] != Version) {
        throw std::runtime_error("Unsupported hybrid package version.");
    }

    const std::uint32_t encryptedKeyLength =
        readUint32LittleEndian(encoded.subspan(1U, 4U));
    const std::uint32_t ciphertextLength =
        readUint32LittleEndian(encoded.subspan(5U, 4U));

    if (encryptedKeyLength == 0
        || ciphertextLength == 0
        || ciphertextLength % aes::Aes256::BlockSize != 0) {
        invalidPackage();
    }

    std::size_t expectedSize = 0;
    try {
        expectedSize = checkedTotalSize(encryptedKeyLength, ciphertextLength);
    } catch (const std::length_error&) {
        invalidPackage();
    }
    if (encoded.size() != expectedSize) {
        invalidPackage();
    }

    aes::Aes256::Block iv{};
    std::copy_n(encoded.begin() + 9, aes::Aes256::BlockSize, iv.begin());

    const std::size_t encryptedKeyOffset = HeaderSize;
    const std::size_t ciphertextOffset = encryptedKeyOffset + encryptedKeyLength;
    std::vector<std::byte> encryptedSessionKey(
        encoded.begin() + static_cast<std::ptrdiff_t>(encryptedKeyOffset),
        encoded.begin() + static_cast<std::ptrdiff_t>(ciphertextOffset));
    std::vector<std::byte> ciphertext(
        encoded.begin() + static_cast<std::ptrdiff_t>(ciphertextOffset),
        encoded.end());

    return HybridEncryptedData{
        std::move(encryptedSessionKey), iv, std::move(ciphertext)};
}

} // namespace stegowav::crypto::hybrid
