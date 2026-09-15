#pragma once

#include "stegowav/crypto/bigint/BigInteger.hpp"
#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/crypto/rsa/RsaPublicKey.hpp"

namespace stegowav::crypto::rsa {

class RsaPrimitive {
public:
    [[nodiscard]] static bigint::BigInteger publicOperation(
        const bigint::BigInteger& messageRepresentative,
        const RsaPublicKey& key);

    [[nodiscard]] static bigint::BigInteger privateOperation(
        const bigint::BigInteger& ciphertextRepresentative,
        const RsaPrivateKey& key);
};

} // namespace stegowav::crypto::rsa
