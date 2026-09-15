#include "stegowav/steganography/LsbSteganography.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace stegowav::steganography {

std::size_t LsbSteganography::capacityBytes(const audio::PcmBuffer& pcm) const noexcept
{
    return pcm.sampleCount() / 8U;
}

void LsbSteganography::embed(
    audio::PcmBuffer& pcm, std::span<const std::byte> data) const
{
    if (data.size() > capacityBytes(pcm)) {
        throw std::runtime_error("Data exceeds PCM LSB capacity.");
    }

    std::size_t sampleIndex = 0;
    for (const std::byte byte : data) {
        const std::uint8_t value = std::to_integer<std::uint8_t>(byte);
        for (int bitIndex = 7; bitIndex >= 0; --bitIndex) {
            const std::int32_t sample = pcm.sample(sampleIndex);
            const std::uint32_t currentBit = static_cast<std::uint32_t>(sample) & 1U;
            const std::uint32_t desiredBit = (value >> bitIndex) & 1U;

            if (currentBit != desiredBit) {
                pcm.setSample(sampleIndex, desiredBit == 1U ? sample + 1 : sample - 1);
            }
            ++sampleIndex;
        }
    }
}

std::vector<std::byte> LsbSteganography::extract(
    const audio::PcmBuffer& pcm, std::size_t byteCount) const
{
    if (byteCount > capacityBytes(pcm)) {
        throw std::runtime_error("Requested data exceeds PCM LSB capacity.");
    }

    std::vector<std::byte> result(byteCount);
    for (std::size_t byteIndex = 0; byteIndex < byteCount; ++byteIndex) {
        std::uint8_t value = 0;
        for (std::size_t bitIndex = 0; bitIndex < 8; ++bitIndex) {
            const std::int32_t sample = pcm.sample(byteIndex * 8U + bitIndex);
            const auto bit = static_cast<std::uint8_t>(
                static_cast<std::uint32_t>(sample) & 1U);
            value = static_cast<std::uint8_t>((value << 1U) | bit);
        }
        result[byteIndex] = static_cast<std::byte>(value);
    }
    return result;
}

} // namespace stegowav::steganography
