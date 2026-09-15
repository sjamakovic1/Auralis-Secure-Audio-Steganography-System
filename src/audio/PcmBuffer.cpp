#include "stegowav/audio/PcmBuffer.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace stegowav::audio {
namespace {

std::size_t calculateBytesPerSample(std::uint16_t bitsPerSample)
{
    switch (bitsPerSample) {
    case 8:
    case 16:
    case 24:
    case 32:
        return bitsPerSample / 8U;
    default:
        throw std::invalid_argument("Unsupported PCM bit depth: expected 8, 16, 24, or 32 bits.");
    }
}

std::uint32_t byteValue(std::byte value)
{
    return std::to_integer<std::uint8_t>(value);
}

std::int32_t signedValue(std::uint32_t value)
{
    return std::bit_cast<std::int32_t>(value);
}

} // namespace

PcmBuffer::PcmBuffer(std::vector<std::byte>& data, std::uint16_t bitsPerSample)
    : data_(data),
      bitsPerSample_(bitsPerSample),
      bytesPerSample_(calculateBytesPerSample(bitsPerSample))
{
    if (data_.size() % bytesPerSample_ != 0) {
        throw std::invalid_argument("PCM data size is not divisible by bytes per sample.");
    }
}

std::size_t PcmBuffer::sampleCount() const noexcept
{
    return data_.size() / bytesPerSample_;
}

std::uint16_t PcmBuffer::bitsPerSample() const noexcept
{
    return bitsPerSample_;
}

std::size_t PcmBuffer::bytesPerSample() const noexcept
{
    return bytesPerSample_;
}

std::int32_t PcmBuffer::sample(std::size_t index) const
{
    if (index >= sampleCount()) {
        throw std::out_of_range("PCM sample index is out of range.");
    }

    const std::size_t offset = index * bytesPerSample_;
    std::uint32_t value = byteValue(data_[offset]);

    for (std::size_t byteIndex = 1; byteIndex < bytesPerSample_; ++byteIndex) {
        value |= byteValue(data_[offset + byteIndex]) << (byteIndex * 8U);
    }

    if (bitsPerSample_ == 8) {
        return static_cast<std::int32_t>(value);
    }
    if (bitsPerSample_ == 16 && (value & 0x00008000U) != 0) {
        value |= 0xFFFF0000U;
    } else if (bitsPerSample_ == 24 && (value & 0x00800000U) != 0) {
        value |= 0xFF000000U;
    }

    return signedValue(value);
}

void PcmBuffer::setSample(std::size_t index, std::int32_t value)
{
    if (index >= sampleCount()) {
        throw std::out_of_range("PCM sample index is out of range.");
    }

    std::int32_t minimum = std::numeric_limits<std::int32_t>::min();
    std::int32_t maximum = std::numeric_limits<std::int32_t>::max();
    switch (bitsPerSample_) {
    case 8:
        minimum = 0;
        maximum = 255;
        break;
    case 16:
        minimum = -32768;
        maximum = 32767;
        break;
    case 24:
        minimum = -8388608;
        maximum = 8388607;
        break;
    case 32:
        break;
    }

    if (value < minimum || value > maximum) {
        throw std::out_of_range("PCM sample value is out of range for the bit depth.");
    }

    const std::uint32_t encoded = static_cast<std::uint32_t>(value);
    const std::size_t offset = index * bytesPerSample_;
    for (std::size_t byteIndex = 0; byteIndex < bytesPerSample_; ++byteIndex) {
        data_[offset + byteIndex] = static_cast<std::byte>(
            (encoded >> (byteIndex * 8U)) & 0xFFU);
    }
}

} // namespace stegowav::audio
