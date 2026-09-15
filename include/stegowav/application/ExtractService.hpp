#pragma once

#include "stegowav/crypto/rsa/RsaPrivateKey.hpp"
#include "stegowav/wav/WavFile.hpp"

#include <cstddef>
#include <vector>

namespace stegowav::application {

class ExtractService {
public:
    [[nodiscard]] static std::vector<std::byte> extract(
        wav::WavFile& wavFile,
        const crypto::rsa::RsaPrivateKey& privateKey);
};

} // namespace stegowav::application
