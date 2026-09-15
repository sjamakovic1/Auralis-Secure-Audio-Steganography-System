#include "stegowav/crypto/hybrid/HybridCipher.hpp"

#include "stegowav/crypto/aes/Aes256Cbc.hpp"
#include "stegowav/crypto/hash/Sha256.hpp"
#include "stegowav/crypto/random/SecureRandom.hpp"
#include "stegowav/crypto/rsa/RsaConversion.hpp"
#include "stegowav/crypto/rsa/RsaOaep.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace stegowav::crypto::hybrid {
namespace {

[[noreturn]] void decryptionFailed()
{
    throw std::runtime_error("Hybrid decryption failed.");
}

void validatePrivateKeyOaepCapacity(const rsa::RsaPrivateKey& privateKey)
{
    const std::size_t modulusLength =
        rsa::RsaConversion::modulusByteLength(privateKey.modulus());
    constexpr std::size_t minimumLength = 2U * hash::Sha256::DigestSize + 2U;
    if (modulusLength < minimumLength) {
        throw std::invalid_argument(
            "RSA modulus is too small for OAEP with SHA-256.");
    }
}

} // namespace

HybridEncryptedData HybridCipher::encrypt(
    std::span<const std::byte> plaintext,
    const rsa::RsaPublicKey& publicKey)
{
    if (rsa::RsaOaep::maximumMessageLength(publicKey) < aes::Aes256::KeySize) {
        throw std::invalid_argument(
            "RSA modulus cannot encrypt a 32-byte AES session key with OAEP.");
    }

    const auto sessionKeyBytes = random::SecureRandom::bytes(aes::Aes256::KeySize);
    aes::Aes256::Key sessionKey{};
    std::copy(sessionKeyBytes.begin(), sessionKeyBytes.end(), sessionKey.begin());

    auto aesResult = aes::Aes256Cbc::encrypt(plaintext, sessionKey);
    auto encryptedSessionKey = rsa::RsaOaep::encrypt(
        std::span<const std::byte>(sessionKey), publicKey);

    return HybridEncryptedData{
        std::move(encryptedSessionKey),
        aesResult.iv,
        std::move(aesResult.ciphertext)
    };
}

std::vector<std::byte> HybridCipher::decrypt(
    const HybridEncryptedData& encryptedData,
    const rsa::RsaPrivateKey& privateKey)
{
    validatePrivateKeyOaepCapacity(privateKey);

    try {
        const auto sessionKeyBytes = rsa::RsaOaep::decrypt(
            encryptedData.encryptedSessionKey, privateKey);
        if (sessionKeyBytes.size() != aes::Aes256::KeySize) {
            decryptionFailed();
        }

        aes::Aes256::Key sessionKey{};
        std::copy(sessionKeyBytes.begin(), sessionKeyBytes.end(), sessionKey.begin());
        return aes::Aes256Cbc::decrypt(
            encryptedData.ciphertext, sessionKey, encryptedData.iv);
    } catch (const std::domain_error&) {
        decryptionFailed();
    } catch (const std::invalid_argument&) {
        decryptionFailed();
    } catch (const std::runtime_error&) {
        decryptionFailed();
    }
}

} // namespace stegowav::crypto::hybrid
