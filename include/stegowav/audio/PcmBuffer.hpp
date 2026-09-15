#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace stegowav::audio {

class PcmBuffer {
public:
    PcmBuffer(std::vector<std::byte>& data, std::uint16_t bitsPerSample);
    ~PcmBuffer() = default;

    [[nodiscard]] std::size_t sampleCount() const noexcept;
    [[nodiscard]] std::uint16_t bitsPerSample() const noexcept;
    [[nodiscard]] std::size_t bytesPerSample() const noexcept;

    [[nodiscard]] std::int32_t sample(std::size_t index) const;
    void setSample(std::size_t index, std::int32_t value);

private:
    std::vector<std::byte>& data_;
    std::uint16_t bitsPerSample_;
    std::size_t bytesPerSample_;
};

} // namespace stegowav::audio
