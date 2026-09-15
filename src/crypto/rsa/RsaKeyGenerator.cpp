#include "stegowav/crypto/rsa/RsaKeyGenerator.hpp"

#include "stegowav/crypto/prime/PrimeGenerator.hpp"
#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/crypto/rsa/RsaPublicKey.hpp"

#include <cstddef>
#include <stdexcept>

namespace stegowav::crypto::rsa {

RsaKeyPair RsaKeyGenerator::generate(
    std::size_t modulusBits,
    const bigint::BigInteger& publicExponent,
    std::size_t millerRabinRounds)
{
    using bigint::BigInteger;

    if (modulusBits < 5) {
        throw std::invalid_argument("RSA modulus bit length must be at least five.");
    }
    if (publicExponent <= BigInteger{1}) {
        throw std::invalid_argument("RSA public exponent must be greater than one.");
    }
    if (!publicExponent.isOdd()) {
        throw std::invalid_argument("RSA public exponent must be odd.");
    }
    if (millerRabinRounds == 0) {
        throw std::invalid_argument("Miller-Rabin requires at least one round.");
    }

    const std::size_t pBits = modulusBits / 2U;
    const std::size_t qBits = modulusBits - pBits;
    const BigInteger one{1};

    while (true) {
        const BigInteger p = prime::PrimeGenerator::generate(pBits, millerRabinRounds);

        BigInteger q;
        do {
            q = prime::PrimeGenerator::generate(qBits, millerRabinRounds);
        } while (q == p);

        const BigInteger modulus = p * q;
        if (modulus.bitLength() != modulusBits) {
            continue;
        }

        const BigInteger phi = (p - one) * (q - one);
        if (publicExponent >= phi || BigInteger::gcd(publicExponent, phi) != one) {
            continue;
        }

        const BigInteger privateExponent = BigInteger::modInverse(publicExponent, phi);
        return RsaKeyPair(
            RsaPublicKey(modulus, publicExponent),
            RsaPrivateKey(modulus, privateExponent));
    }
}

} // namespace stegowav::crypto::rsa
