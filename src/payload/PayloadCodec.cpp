#include "stegowav/payload/PayloadCodec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace stegowav::payload {
namespace {

constexpr std::array<std::byte, 4> Magic{
    std::byte{'S'}, std::byte{'T'}, std::byte{'E'}, std::byte{'G'}
};
constexpr std::uint8_t CurrentVersion = 1;

void appendUint32LE(std::vector<std::byte>& output, std::uint32_t value)
{
    output.push_back(static_cast<std::byte>(value & 0xFFU));
    output.push_back(static_cast<std::byte>((value >> 8U) & 0xFFU));
    output.push_back(static_cast<std::byte>((value >> 16U) & 0xFFU));
    output.push_back(static_cast<std::byte>((value >> 24U) & 0xFFU));
}

std::uint32_t readUint32LE(std::span<const std::byte> data)
{
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[0]))
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[1])) << 8U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[2])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[3])) << 24U);
}

} // namespace

std::vector<std::byte> PayloadCodec::encode(const Payload& payload) const
{
    if (payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("Payload is too large to encode.");
    }

    std::vector<std::byte> encoded;
    encoded.reserve(HeaderSize + payload.size());
    encoded.insert(encoded.end(), Magic.begin(), Magic.end());
    encoded.push_back(static_cast<std::byte>(CurrentVersion));
    appendUint32LE(encoded, static_cast<std::uint32_t>(payload.size()));
    encoded.insert(encoded.end(), payload.data().begin(), payload.data().end());
    return encoded;
}

PayloadHeader PayloadCodec::decodeHeader(std::span<const std::byte> data) const
{
    if (data.size() < HeaderSize) {
        throw std::runtime_error("Payload header is truncated.");
    }
    for (std::size_t index = 0; index < Magic.size(); ++index) {
        if (data[index] != Magic[index]) {
            throw std::runtime_error("Invalid StegoWAV payload signature.");
        }
    }

    const std::uint8_t version = std::to_integer<std::uint8_t>(data[4]);
    if (version != CurrentVersion) {
        throw std::runtime_error("Unsupported payload version.");
    }

    return PayloadHeader{version, readUint32LE(data.subspan(5, 4))};
}

Payload PayloadCodec::decode(std::span<const std::byte> encoded) const
{
    const PayloadHeader header = decodeHeader(encoded);
    if (header.dataSize > std::numeric_limits<std::size_t>::max() - HeaderSize) {
        throw std::runtime_error("Encoded payload size overflows the platform size.");
    }

    const std::size_t totalSize = HeaderSize + static_cast<std::size_t>(header.dataSize);
    if (encoded.size() < totalSize) {
        throw std::runtime_error("Encoded payload is truncated.");
    }

    return Payload(std::vector<std::byte>(
        encoded.begin() + static_cast<std::ptrdiff_t>(HeaderSize),
        encoded.begin() + static_cast<std::ptrdiff_t>(totalSize)));
}

} // namespace stegowav::payload
