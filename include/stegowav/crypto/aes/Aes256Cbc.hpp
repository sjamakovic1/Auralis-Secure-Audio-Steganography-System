#pragma once

#include "stegowav/crypto/aes/Aes256.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace stegowav::crypto::aes {

struct Aes256CbcEncryptedData {
    Aes256::Block iv;
    std::vector<std::byte> ciphertext;
};

class Aes256Cbc {
public:
    [[nodiscard]] static Aes256CbcEncryptedData encrypt(
        std::span<const std::byte> plaintext,
        const Aes256::Key& key);

    [[nodiscard]] static std::vector<std::byte> decrypt(
        std::span<const std::byte> ciphertext,
        const Aes256::Key& key,
        const Aes256::Block& iv);
};

} // namespace stegowav::crypto::aes
