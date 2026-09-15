#include "stegowav/crypto/rsa/RsaConversion.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace stegowav::crypto::rsa {

bigint::BigInteger RsaConversion::os2ip(std::span<const std::byte> octets)
{
    return bigint::BigInteger::fromBytes(octets);
}

std::vector<std::byte> RsaConversion::i2osp(
    const bigint::BigInteger& value, std::size_t length)
{
    if (length == 0) {
        if (value.isZero()) {
            return {};
        }
        throw std::overflow_error(
            "Integer is too large for the requested zero-length octet string.");
    }

    const std::vector<std::byte> minimal = value.toBytes();
    if (minimal.size() > length) {
        throw std::overflow_error(
            "Integer is too large for the requested octet string length.");
    }

    std::vector<std::byte> result(length, std::byte{0});
    std::copy(minimal.begin(), minimal.end(), result.end() - minimal.size());
    return result;
}

std::size_t RsaConversion::modulusByteLength(
    const bigint::BigInteger& modulus)
{
    if (modulus.isZero()) {
        throw std::invalid_argument("RSA modulus must not be zero.");
    }

    const std::size_t bits = modulus.bitLength();
    return bits / 8U + (bits % 8U != 0 ? 1U : 0U);
}

} // namespace stegowav::crypto::rsa
