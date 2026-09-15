#pragma once

#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/crypto/rsa/RsaPublicKey.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::rsa {

class RsaOaep {
public:
    [[nodiscard]] static std::vector<std::byte> encrypt(
        std::span<const std::byte> message,
        const RsaPublicKey& publicKey);

    [[nodiscard]] static std::vector<std::byte> decrypt(
        std::span<const std::byte> ciphertext,
        const RsaPrivateKey& privateKey);

    [[nodiscard]] static std::size_t maximumMessageLength(
        const RsaPublicKey& publicKey);
};

} // namespace stegowav::crypto::rsa
