#pragma once

#include "stegowav/crypto/aes/Aes256.hpp"
#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/crypto/rsa/RsaPublicKey.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::hybrid {

struct HybridEncryptedData {
    std::vector<std::byte> encryptedSessionKey;
    aes::Aes256::Block iv;
    std::vector<std::byte> ciphertext;
};

class HybridCipher {
public:
    [[nodiscard]] static HybridEncryptedData encrypt(
        std::span<const std::byte> plaintext,
        const rsa::RsaPublicKey& publicKey);

    [[nodiscard]] static std::vector<std::byte> decrypt(
        const HybridEncryptedData& encryptedData,
        const rsa::RsaPrivateKey& privateKey);
};

} // namespace stegowav::crypto::hybrid
