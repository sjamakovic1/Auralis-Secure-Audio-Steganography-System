#pragma once

#include "stegowav/crypto/rsa/RsaPublicKey.hpp"
#include "stegowav/wav/WavFile.hpp"

#include <cstddef>
#include <span>

namespace stegowav::application {

class EmbedService {
public:
    static void embed(
        wav::WavFile& wavFile,
        std::span<const std::byte> plaintext,
        const crypto::rsa::RsaPublicKey& publicKey);
};

} // namespace stegowav::application
