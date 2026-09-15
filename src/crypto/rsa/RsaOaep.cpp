#include "stegowav/crypto/rsa/RsaOaep.hpp"

#include "stegowav/crypto/hash/Sha256.hpp"
#include "stegowav/crypto/oaep/OaepCodec.hpp"
#include "stegowav/crypto/rsa/RsaConversion.hpp"
#include "stegowav/crypto/rsa/RsaPrimitive.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace stegowav::crypto::rsa {
namespace {

std::size_t maximumMessageLengthForModulus(std::size_t modulusLength)
{
    constexpr std::size_t hashLength = hash::Sha256::DigestSize;
    constexpr std::size_t minimumModulusLength = 2U * hashLength + 2U;
    if (modulusLength < minimumModulusLength) {
        throw std::invalid_argument("RSA modulus is too small for OAEP with SHA-256.");
    }
    return modulusLength - minimumModulusLength;
}

[[noreturn]] void decryptionFailed()
{
    throw std::runtime_error("RSAES-OAEP decryption failed.");
}

} // namespace

std::size_t RsaOaep::maximumMessageLength(const RsaPublicKey& publicKey)
{
    const std::size_t modulusLength =
        RsaConversion::modulusByteLength(publicKey.modulus());
    return maximumMessageLengthForModulus(modulusLength);
}

std::vector<std::byte> RsaOaep::encrypt(
    std::span<const std::byte> message,
    const RsaPublicKey& publicKey)
{
    const std::size_t modulusLength =
        RsaConversion::modulusByteLength(publicKey.modulus());
    static_cast<void>(maximumMessageLengthForModulus(modulusLength));

    const auto encodedMessage = oaep::OaepCodec::encode(message, modulusLength);
    const auto messageRepresentative = RsaConversion::os2ip(encodedMessage);
    const auto ciphertextRepresentative = RsaPrimitive::publicOperation(
        messageRepresentative, publicKey);
    return RsaConversion::i2osp(ciphertextRepresentative, modulusLength);
}

std::vector<std::byte> RsaOaep::decrypt(
    std::span<const std::byte> ciphertext,
    const RsaPrivateKey& privateKey)
{
    const std::size_t modulusLength =
        RsaConversion::modulusByteLength(privateKey.modulus());
    static_cast<void>(maximumMessageLengthForModulus(modulusLength));

    if (ciphertext.size() != modulusLength) {
        decryptionFailed();
    }

    try {
        const auto ciphertextRepresentative = RsaConversion::os2ip(ciphertext);
        const auto messageRepresentative = RsaPrimitive::privateOperation(
            ciphertextRepresentative, privateKey);
        const auto encodedMessage = RsaConversion::i2osp(
            messageRepresentative, modulusLength);
        return oaep::OaepCodec::decode(encodedMessage);
    } catch (const std::runtime_error&) {
        decryptionFailed();
    }
}

} // namespace stegowav::crypto::rsa
