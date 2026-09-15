#include "stegowav/crypto/rsa/RsaKeyCodec.hpp"

#include "stegowav/crypto/bigint/BigInteger.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace stegowav::crypto::rsa {
namespace {

constexpr std::array<std::byte, 4> Magic{
    std::byte{'S'}, std::byte{'W'}, std::byte{'K'}, std::byte{'Y'}
};
constexpr std::byte Version{0x01};
constexpr std::byte PublicKeyType{0x01};
constexpr std::byte PrivateKeyType{0x02};

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

[[noreturn]] void invalidKeyFormat()
{
    throw std::runtime_error("Invalid RSA key format.");
}

std::size_t checkedEncodedSize(std::size_t modulusLength, std::size_t exponentLength)
{
    constexpr std::size_t maximum = std::numeric_limits<std::size_t>::max();
    if (modulusLength > maximum - RsaKeyCodec::HeaderSize) {
        throw std::length_error("RSA key encoding is too large.");
    }
    const std::size_t headerAndModulus = RsaKeyCodec::HeaderSize + modulusLength;
    if (exponentLength > maximum - headerAndModulus) {
        throw std::length_error("RSA key encoding is too large.");
    }
    return headerAndModulus + exponentLength;
}

std::vector<std::byte> encodeKey(
    const bigint::BigInteger& modulus,
    const bigint::BigInteger& exponent,
    std::byte keyType)
{
    if (modulus.isZero() || exponent.isZero()) {
        throw std::invalid_argument("RSA modulus and exponent must not be zero.");
    }

    const auto modulusBytes = modulus.toBytes();
    const auto exponentBytes = exponent.toBytes();
    if (modulusBytes.size() > std::numeric_limits<std::uint32_t>::max()
        || exponentBytes.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("RSA key integer is too large to encode.");
    }

    const std::size_t totalSize = checkedEncodedSize(
        modulusBytes.size(), exponentBytes.size());
    std::vector<std::byte> encoded;
    encoded.reserve(totalSize);
    encoded.insert(encoded.end(), Magic.begin(), Magic.end());
    encoded.push_back(Version);
    encoded.push_back(keyType);
    appendUint32LittleEndian(encoded, static_cast<std::uint32_t>(modulusBytes.size()));
    appendUint32LittleEndian(encoded, static_cast<std::uint32_t>(exponentBytes.size()));
    encoded.insert(encoded.end(), modulusBytes.begin(), modulusBytes.end());
    encoded.insert(encoded.end(), exponentBytes.begin(), exponentBytes.end());
    return encoded;
}

struct DecodedKeyValues {
    bigint::BigInteger modulus;
    bigint::BigInteger exponent;
};

DecodedKeyValues decodeKey(std::span<const std::byte> encoded, std::byte expectedType)
{
    if (encoded.size() < RsaKeyCodec::HeaderSize) {
        invalidKeyFormat();
    }
    for (std::size_t index = 0; index < Magic.size(); ++index) {
        if (encoded[index] != Magic[index]) {
            invalidKeyFormat();
        }
    }
    if (encoded[4] != Version) {
        throw std::runtime_error("Unsupported RSA key format version.");
    }
    if (encoded[5] != expectedType) {
        throw std::runtime_error(
            expectedType == PublicKeyType
                ? "RSA key is not a public key."
                : "RSA key is not a private key.");
    }

    const std::uint32_t modulusLength =
        readUint32LittleEndian(encoded.subspan(6U, 4U));
    const std::uint32_t exponentLength =
        readUint32LittleEndian(encoded.subspan(10U, 4U));
    if (modulusLength == 0 || exponentLength == 0) {
        invalidKeyFormat();
    }

    std::size_t expectedSize = 0;
    try {
        expectedSize = checkedEncodedSize(modulusLength, exponentLength);
    } catch (const std::length_error&) {
        invalidKeyFormat();
    }
    if (encoded.size() != expectedSize) {
        invalidKeyFormat();
    }

    const auto modulusBytes = encoded.subspan(RsaKeyCodec::HeaderSize, modulusLength);
    const auto exponentBytes = encoded.subspan(
        RsaKeyCodec::HeaderSize + modulusLength, exponentLength);
    auto modulus = bigint::BigInteger::fromBytes(modulusBytes);
    auto exponent = bigint::BigInteger::fromBytes(exponentBytes);
    if (modulus.isZero() || exponent.isZero()) {
        invalidKeyFormat();
    }
    return {std::move(modulus), std::move(exponent)};
}

} // namespace

std::vector<std::byte> RsaKeyCodec::encode(const RsaPublicKey& key)
{
    return encodeKey(key.modulus(), key.exponent(), PublicKeyType);
}

std::vector<std::byte> RsaKeyCodec::encode(const RsaPrivateKey& key)
{
    return encodeKey(key.modulus(), key.exponent(), PrivateKeyType);
}

RsaPublicKey RsaKeyCodec::decodePublic(std::span<const std::byte> encoded)
{
    auto values = decodeKey(encoded, PublicKeyType);
    return RsaPublicKey(std::move(values.modulus), std::move(values.exponent));
}

RsaPrivateKey RsaKeyCodec::decodePrivate(std::span<const std::byte> encoded)
{
    auto values = decodeKey(encoded, PrivateKeyType);
    return RsaPrivateKey(std::move(values.modulus), std::move(values.exponent));
}

} // namespace stegowav::crypto::rsa
