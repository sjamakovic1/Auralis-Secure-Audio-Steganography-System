#pragma once

#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/crypto/rsa/RsaPublicKey.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::rsa {

class RsaKeyCodec {
public:
    static constexpr std::size_t HeaderSize = 14;

    [[nodiscard]] static std::vector<std::byte> encode(
        const RsaPublicKey& key);
    [[nodiscard]] static std::vector<std::byte> encode(
        const RsaPrivateKey& key);

    [[nodiscard]] static RsaPublicKey decodePublic(
        std::span<const std::byte> encoded);
    [[nodiscard]] static RsaPrivateKey decodePrivate(
        std::span<const std::byte> encoded);
};

} // namespace stegowav::crypto::rsa
