#include "stegowav/crypto/padding/Pkcs7.hpp"

#include <cstddef>
#include <limits>
#include <stdexcept>
#include <vector>

namespace stegowav::crypto::padding {
namespace {

void validateBlockSize(std::size_t blockSize)
{
    if (blockSize == 0 || blockSize > 255) {
        throw std::invalid_argument("PKCS#7 block size must be between 1 and 255 bytes.");
    }
}

[[noreturn]] void invalidPadding()
{
    throw std::runtime_error("Invalid PKCS#7 padding.");
}

} // namespace

std::vector<std::byte> Pkcs7::pad(
    std::span<const std::byte> data, std::size_t blockSize)
{
    validateBlockSize(blockSize);
    const std::size_t paddingLength = blockSize - (data.size() % blockSize);
    if (data.size() > std::numeric_limits<std::size_t>::max() - paddingLength) {
        throw std::length_error("PKCS#7 padded data size is too large.");
    }

    std::vector<std::byte> result;
    result.reserve(data.size() + paddingLength);
    result.insert(result.end(), data.begin(), data.end());
    result.insert(
        result.end(), paddingLength, static_cast<std::byte>(paddingLength));
    return result;
}

std::vector<std::byte> Pkcs7::unpad(
    std::span<const std::byte> data, std::size_t blockSize)
{
    validateBlockSize(blockSize);
    if (data.empty() || data.size() % blockSize != 0) {
        invalidPadding();
    }

    const std::size_t paddingLength = std::to_integer<unsigned int>(data.back());
    if (paddingLength == 0
        || paddingLength > blockSize
        || paddingLength > data.size()) {
        invalidPadding();
    }

    bool valid = true;
    const std::byte expected = static_cast<std::byte>(paddingLength);
    for (std::size_t index = data.size() - paddingLength; index < data.size(); ++index) {
        valid = (data[index] == expected) && valid;
    }
    if (!valid) {
        invalidPadding();
    }

    return std::vector<std::byte>(
        data.begin(), data.end() - static_cast<std::ptrdiff_t>(paddingLength));
}

} // namespace stegowav::crypto::padding
