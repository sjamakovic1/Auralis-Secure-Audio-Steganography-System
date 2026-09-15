#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::oaep {

class OaepCodec {
public:
    [[nodiscard]] static std::vector<std::byte> encode(
        std::span<const std::byte> message, std::size_t encodedLength);

    [[nodiscard]] static std::vector<std::byte> decode(
        std::span<const std::byte> encodedMessage);
};

} // namespace stegowav::crypto::oaep
