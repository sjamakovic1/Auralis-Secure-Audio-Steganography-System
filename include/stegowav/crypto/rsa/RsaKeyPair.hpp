#pragma once

#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/crypto/rsa/RsaPublicKey.hpp"

#include <utility>

namespace stegowav::crypto::rsa {

class RsaKeyPair {
public:
    RsaKeyPair(RsaPublicKey publicKey, RsaPrivateKey privateKey)
        : publicKey_(std::move(publicKey)), privateKey_(std::move(privateKey))
    {
    }

    [[nodiscard]] const RsaPublicKey& publicKey() const noexcept
    {
        return publicKey_;
    }

    [[nodiscard]] const RsaPrivateKey& privateKey() const noexcept
    {
        return privateKey_;
    }

private:
    RsaPublicKey publicKey_;
    RsaPrivateKey privateKey_;
};

} // namespace stegowav::crypto::rsa
