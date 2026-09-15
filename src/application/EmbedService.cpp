#include "stegowav/application/EmbedService.hpp"

#include "stegowav/audio/PcmBuffer.hpp"
#include "stegowav/crypto/hybrid/HybridCipher.hpp"
#include "stegowav/crypto/hybrid/HybridPackageCodec.hpp"
#include "stegowav/payload/Payload.hpp"
#include "stegowav/payload/PayloadCodec.hpp"
#include "stegowav/steganography/LsbSteganography.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>

namespace stegowav::application {

void EmbedService::embed(
    wav::WavFile& wavFile,
    std::span<const std::byte> plaintext,
    const crypto::rsa::RsaPublicKey& publicKey)
{
    const auto encrypted = crypto::hybrid::HybridCipher::encrypt(
        plaintext, publicKey);
    auto hybridBytes = crypto::hybrid::HybridPackageCodec::encode(encrypted);

    const payload::Payload payload(std::move(hybridBytes));
    const payload::PayloadCodec payloadCodec;
    const auto encodedPayload = payloadCodec.encode(payload);

    audio::PcmBuffer pcmBuffer(
        wavFile.audioData(), wavFile.format().bitsPerSample);
    const steganography::LsbSteganography lsb;
    if (encodedPayload.size() > lsb.capacityBytes(pcmBuffer)) {
        throw std::length_error("Encrypted payload exceeds WAV LSB capacity.");
    }

    lsb.embed(pcmBuffer, encodedPayload);
}

} // namespace stegowav::application
