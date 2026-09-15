#include "stegowav/crypto/rsa/RsaPrimitive.hpp"

#include <stdexcept>

namespace stegowav::crypto::rsa {

bigint::BigInteger RsaPrimitive::publicOperation(
    const bigint::BigInteger& messageRepresentative,
    const RsaPublicKey& key)
{
    if (key.modulus().isZero()) {
        throw std::domain_error("RSA public key modulus must not be zero.");
    }
    if (messageRepresentative >= key.modulus()) {
        throw std::domain_error(
            "RSA message representative must be smaller than the modulus.");
    }

    return bigint::BigInteger::modPow(
        messageRepresentative, key.exponent(), key.modulus());
}

bigint::BigInteger RsaPrimitive::privateOperation(
    const bigint::BigInteger& ciphertextRepresentative,
    const RsaPrivateKey& key)
{
    if (key.modulus().isZero()) {
        throw std::domain_error("RSA private key modulus must not be zero.");
    }
    if (ciphertextRepresentative >= key.modulus()) {
        throw std::domain_error(
            "RSA ciphertext representative must be smaller than the modulus.");
    }

    return bigint::BigInteger::modPow(
        ciphertextRepresentative, key.exponent(), key.modulus());
}

} // namespace stegowav::crypto::rsa
