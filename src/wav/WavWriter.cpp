#include "stegowav/wav/WavWriter.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace stegowav::wav {
namespace {

void writeExact(std::ostream& output, const char* data, std::streamsize size)
{
    output.write(data, size);
    if (!output) {
        throw std::runtime_error("Failed while writing WAV file.");
    }
}

void writeUint32LE(std::ostream& output, std::uint32_t value)
{
    const std::array<char, 4> bytes{
        static_cast<char>(value & 0xFFU),
        static_cast<char>((value >> 8U) & 0xFFU),
        static_cast<char>((value >> 16U) & 0xFFU),
        static_cast<char>((value >> 24U) & 0xFFU)
    };
    writeExact(output, bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::uint32_t calculateRiffSize(const WavFile& wav)
{
    std::uint64_t size = 4;
    for (const auto& chunk : wav.chunks()) {
        if (chunk.data.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("RIFF chunk is too large to write.");
        }
        size += 8U + chunk.data.size() + (chunk.data.size() % 2U);
        if (size > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("WAV file is too large for the RIFF format.");
        }
    }
    return static_cast<std::uint32_t>(size);
}

} // namespace

void WavWriter::write(const WavFile& wav, const std::filesystem::path& path) const
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Could not open output WAV file: " + path.string());
    }

    writeExact(output, "RIFF", 4);
    writeUint32LE(output, calculateRiffSize(wav));
    writeExact(output, "WAVE", 4);

    for (const auto& chunk : wav.chunks()) {
        writeExact(output, chunk.id.data(), static_cast<std::streamsize>(chunk.id.size()));
        writeUint32LE(output, static_cast<std::uint32_t>(chunk.data.size()));
        if (!chunk.data.empty()) {
            writeExact(output, reinterpret_cast<const char*>(chunk.data.data()),
                       static_cast<std::streamsize>(chunk.data.size()));
        }
        if (chunk.data.size() % 2U != 0) {
            const char padding = 0;
            writeExact(output, &padding, 1);
        }
    }
}

} // namespace stegowav::wav
