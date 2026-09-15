#include "stegowav/wav/WavReader.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace stegowav::wav {
namespace {

void readExact(std::istream& input, char* destination, std::streamsize size)
{
    if (!input.read(destination, size)) {
        throw std::runtime_error("Unexpected end of WAV file.");
    }
}

std::uint16_t readUint16LE(const std::byte* bytes)
{
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[0]))
        | (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[1])) << 8U);
}

std::uint32_t readUint32LE(const std::byte* bytes)
{
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[0]))
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 8U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3])) << 24U);
}

std::uint32_t readUint32LE(std::istream& input)
{
    std::array<std::byte, 4> bytes{};
    readExact(input, reinterpret_cast<char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return readUint32LE(bytes.data());
}

bool matches(const std::array<char, 4>& value, std::string_view expected)
{
    return std::string_view(value.data(), value.size()) == expected;
}

} // namespace

WavFile WavReader::read(const std::filesystem::path& path) const
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Could not open WAV file: " + path.string());
    }

    std::array<char, 4> signature{};
    readExact(input, signature.data(), static_cast<std::streamsize>(signature.size()));
    if (!matches(signature, "RIFF")) {
        throw std::runtime_error("File is not a RIFF file.");
    }

    const std::uint32_t riffSize = readUint32LE(input);
    readExact(input, signature.data(), static_cast<std::streamsize>(signature.size()));
    if (!matches(signature, "WAVE")) {
        throw std::runtime_error("RIFF file is not a WAVE file.");
    }
    if (riffSize < 4) {
        throw std::runtime_error("Invalid RIFF chunk size.");
    }

    std::uint64_t remaining = static_cast<std::uint64_t>(riffSize) - 4U;
    WavFormat format{};
    std::vector<RiffChunk> chunks;
    bool foundFormat = false;
    bool foundData = false;

    while (remaining > 0) {
        if (remaining < 8) {
            throw std::runtime_error("Unexpected end of RIFF chunk data.");
        }

        std::array<char, 4> chunkId{};
        readExact(input, chunkId.data(), static_cast<std::streamsize>(chunkId.size()));
        const std::uint32_t chunkSize = readUint32LE(input);
        remaining -= 8;

        const std::uint64_t paddedSize = static_cast<std::uint64_t>(chunkSize)
            + (chunkSize % 2U);
        if (paddedSize > remaining) {
            throw std::runtime_error("Unexpected end of RIFF chunk data.");
        }

        RiffChunk chunk;
        chunk.id = chunkId;
        chunk.data.resize(chunkSize);
        if (chunkSize > 0) {
            readExact(input, reinterpret_cast<char*>(chunk.data.data()),
                      static_cast<std::streamsize>(chunk.data.size()));
        }

        if (matches(chunkId, "fmt ") && !foundFormat) {
            if (chunkSize < 16) {
                throw std::runtime_error("The fmt chunk is smaller than 16 bytes.");
            }

            format.audioFormat = readUint16LE(chunk.data.data());
            format.numChannels = readUint16LE(chunk.data.data() + 2);
            format.sampleRate = readUint32LE(chunk.data.data() + 4);
            format.byteRate = readUint32LE(chunk.data.data() + 8);
            format.blockAlign = readUint16LE(chunk.data.data() + 12);
            format.bitsPerSample = readUint16LE(chunk.data.data() + 14);

            if (format.audioFormat != 1) {
                throw std::runtime_error("Unsupported WAV format: only PCM is supported.");
            }

            foundFormat = true;
        } else if (matches(chunkId, "data") && !foundData) {
            foundData = true;
        }

        chunks.push_back(std::move(chunk));

        if (chunkSize % 2U != 0) {
            char padding{};
            readExact(input, &padding, 1);
        }
        remaining -= paddedSize;
    }

    if (!foundFormat) {
        throw std::runtime_error("WAV file does not contain a fmt chunk.");
    }
    if (!foundData) {
        throw std::runtime_error("WAV file does not contain a data chunk.");
    }

    return WavFile(format, std::move(chunks));
}

} // namespace stegowav::wav
