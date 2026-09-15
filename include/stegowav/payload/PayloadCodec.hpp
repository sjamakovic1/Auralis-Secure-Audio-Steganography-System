#pragma once

#include "stegowav/payload/Payload.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace stegowav::payload {

struct PayloadHeader {
    std::uint8_t version{};
    std::uint32_t dataSize{};
};

class PayloadCodec {
public:
    static constexpr std::size_t HeaderSize = 9;

    PayloadCodec() = default;
    ~PayloadCodec() = default;

    [[nodiscard]] std::vector<std::byte> encode(const Payload& payload) const;
    [[nodiscard]] PayloadHeader decodeHeader(std::span<const std::byte> data) const;
    [[nodiscard]] Payload decode(std::span<const std::byte> encoded) const;
};

} // namespace stegowav::payload
