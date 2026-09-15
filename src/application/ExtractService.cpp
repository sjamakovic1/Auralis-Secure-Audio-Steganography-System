#include "stegowav/application/ExtractService.hpp"

#include "stegowav/audio/PcmBuffer.hpp"
#include "stegowav/crypto/hybrid/HybridCipher.hpp"
#include "stegowav/crypto/hybrid/HybridPackageCodec.hpp"
#include "stegowav/payload/PayloadCodec.hpp"
#include "stegowav/steganography/LsbSteganography.hpp"

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <vector>

namespace stegowav::application {
namespace {

[[noreturn]] void noPayloadFound()
{
    throw std::runtime_error("No valid StegoWAV payload found.");
}

[[noreturn]] void invalidPayloadLength()
{
    throw std::runtime_error("Invalid StegoWAV payload length.");
}

[[noreturn]] void hybridDecryptionFailed()
{
    throw std::runtime_error("Hybrid decryption failed.");
}

} // namespace

std::vector<std::byte> ExtractService::extract(
    wav::WavFile& wavFile,
    const crypto::rsa::RsaPrivateKey& privateKey)
{
    audio::PcmBuffer pcmBuffer(
        wavFile.audioData(), wavFile.format().bitsPerSample);
    const steganography::LsbSteganography lsb;
    const std::size_t capacity = lsb.capacityBytes(pcmBuffer);

    if (capacity < payload::PayloadCodec::HeaderSize) {
        noPayloadFound();
    }

    const auto headerBytes = lsb.extract(
        pcmBuffer, payload::PayloadCodec::HeaderSize);
    const payload::PayloadCodec payloadCodec;

    payload::PayloadHeader header{};
    try {
        header = payloadCodec.decodeHeader(headerBytes);
    } catch (const std::runtime_error&) {
        noPayloadFound();
    }

    constexpr std::size_t maximumSize = std::numeric_limits<std::size_t>::max();
    if (header.dataSize > maximumSize - payload::PayloadCodec::HeaderSize) {
        invalidPayloadLength();
    }
    const std::size_t totalPayloadSize = payload::PayloadCodec::HeaderSize
        + static_cast<std::size_t>(header.dataSize);
    if (totalPayloadSize > capacity) {
        invalidPayloadLength();
    }

    const auto encodedPayload = lsb.extract(pcmBuffer, totalPayloadSize);
    const auto decodedPayload = payloadCodec.decode(encodedPayload);

    try {
        const auto hybridData = crypto::hybrid::HybridPackageCodec::decode(
            decodedPayload.data());
        return crypto::hybrid::HybridCipher::decrypt(hybridData, privateKey);
    } catch (const std::runtime_error&) {
        hybridDecryptionFailed();
    }
}

} // namespace stegowav::application
