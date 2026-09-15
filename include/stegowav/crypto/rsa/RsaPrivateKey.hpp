#pragma once

#include "stegowav/crypto/bigint/BigInteger.hpp"

#include <utility>

namespace stegowav::crypto::rsa {

class RsaPrivateKey {
public:
    RsaPrivateKey(bigint::BigInteger modulus, bigint::BigInteger exponent)
        : modulus_(std::move(modulus)), exponent_(std::move(exponent))
    {
    }

    [[nodiscard]] const bigint::BigInteger& modulus() const noexcept
    {
        return modulus_;
    }

    [[nodiscard]] const bigint::BigInteger& exponent() const noexcept
    {
        return exponent_;
    }

private:
    bigint::BigInteger modulus_;
    bigint::BigInteger exponent_;
};

} // namespace stegowav::crypto::rsa
