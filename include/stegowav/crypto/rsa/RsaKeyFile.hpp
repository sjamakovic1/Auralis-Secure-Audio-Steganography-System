#pragma once

#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/crypto/rsa/RsaPublicKey.hpp"

#include <filesystem>

namespace stegowav::crypto::rsa {

class RsaKeyFile {
public:
    static void savePublic(
        const std::filesystem::path& path, const RsaPublicKey& key);
    static void savePrivate(
        const std::filesystem::path& path, const RsaPrivateKey& key);

    [[nodiscard]] static RsaPublicKey loadPublic(
        const std::filesystem::path& path);
    [[nodiscard]] static RsaPrivateKey loadPrivate(
        const std::filesystem::path& path);
};

} // namespace stegowav::crypto::rsa
