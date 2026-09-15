#include "stegowav/crypto/rsa/RsaKeyFile.hpp"

#include "stegowav/crypto/rsa/RsaKeyCodec.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace stegowav::crypto::rsa {
namespace {

constexpr std::size_t IoChunkSize = 1024U * 1024U;

void writeFile(
    const std::filesystem::path& path,
    std::span<const std::byte> data)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Could not open RSA key file for writing: " + path.string());
    }

    std::size_t offset = 0;
    while (offset < data.size()) {
        const std::size_t count = std::min(IoChunkSize, data.size() - offset);
        output.write(
            reinterpret_cast<const char*>(data.data() + offset),
            static_cast<std::streamsize>(count));
        if (!output) {
            throw std::runtime_error("Failed while writing RSA key file: " + path.string());
        }
        offset += count;
    }
    output.flush();
    if (!output) {
        throw std::runtime_error("Failed while writing RSA key file: " + path.string());
    }
}

std::vector<std::byte> readFile(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("Could not open RSA key file for reading: " + path.string());
    }

    const std::streamoff endPosition = input.tellg();
    if (endPosition < 0) {
        throw std::runtime_error("Could not determine RSA key file size: " + path.string());
    }
    const auto unsignedSize = static_cast<std::uintmax_t>(endPosition);
    if (unsignedSize > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("RSA key file is too large to load: " + path.string());
    }

    const std::size_t size = static_cast<std::size_t>(unsignedSize);
    std::vector<std::byte> data(size);
    input.seekg(0, std::ios::beg);
    if (!input) {
        throw std::runtime_error("Could not seek in RSA key file: " + path.string());
    }

    std::size_t offset = 0;
    while (offset < data.size()) {
        const std::size_t count = std::min(IoChunkSize, data.size() - offset);
        input.read(
            reinterpret_cast<char*>(data.data() + offset),
            static_cast<std::streamsize>(count));
        if (!input) {
            throw std::runtime_error("Failed while reading RSA key file: " + path.string());
        }
        offset += count;
    }
    return data;
}

} // namespace

void RsaKeyFile::savePublic(
    const std::filesystem::path& path, const RsaPublicKey& key)
{
    writeFile(path, RsaKeyCodec::encode(key));
}

void RsaKeyFile::savePrivate(
    const std::filesystem::path& path, const RsaPrivateKey& key)
{
    writeFile(path, RsaKeyCodec::encode(key));
}

RsaPublicKey RsaKeyFile::loadPublic(const std::filesystem::path& path)
{
    return RsaKeyCodec::decodePublic(readFile(path));
}

RsaPrivateKey RsaKeyFile::loadPrivate(const std::filesystem::path& path)
{
    return RsaKeyCodec::decodePrivate(readFile(path));
}

} // namespace stegowav::crypto::rsa
