#include "stegowav/crypto/oaep/OaepCodec.hpp"

#include "stegowav/crypto/hash/Sha256.hpp"
#include "stegowav/crypto/mgf/Mgf1.hpp"
#include "stegowav/crypto/random/SecureRandom.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace stegowav::crypto::oaep {
namespace {

std::vector<std::byte> xorBytes(
    std::span<const std::byte> left, std::span<const std::byte> right)
{
    if (left.size() != right.size()) {
        throw std::logic_error("Cannot XOR byte sequences of different lengths.");
    }

    std::vector<std::byte> result(left.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        result[index] = left[index] ^ right[index];
    }
    return result;
}

std::span<const std::byte> emptyLabel() noexcept
{
    return {};
}

[[noreturn]] void decodingFailed()
{
    throw std::runtime_error("OAEP decoding failed.");
}

} // namespace

std::vector<std::byte> OaepCodec::encode(
    std::span<const std::byte> message, std::size_t encodedLength)
{
    constexpr std::size_t hashLength = hash::Sha256::DigestSize;
    constexpr std::size_t minimumEncodedLength = 2U * hashLength + 2U;

    if (encodedLength < minimumEncodedLength) {
        throw std::invalid_argument("OAEP encoded length is too small for SHA-256.");
    }

    const std::size_t maximumMessageLength = encodedLength - minimumEncodedLength;
    if (message.size() > maximumMessageLength) {
        throw std::length_error("Message is too long for the OAEP encoded length.");
    }

    const auto labelHash = hash::Sha256::digest(emptyLabel());
    const std::size_t paddingLength = maximumMessageLength - message.size();
    const std::size_t dataBlockLength = encodedLength - hashLength - 1U;

    std::vector<std::byte> dataBlock;
    dataBlock.reserve(dataBlockLength);
    dataBlock.insert(dataBlock.end(), labelHash.begin(), labelHash.end());
    dataBlock.insert(dataBlock.end(), paddingLength, std::byte{0});
    dataBlock.push_back(std::byte{1});
    dataBlock.insert(dataBlock.end(), message.begin(), message.end());

    const auto seed = random::SecureRandom::bytes(hashLength);
    const auto dataBlockMask = mgf::Mgf1::generate(seed, dataBlockLength);
    const auto maskedDataBlock = xorBytes(dataBlock, dataBlockMask);
    const auto seedMask = mgf::Mgf1::generate(maskedDataBlock, hashLength);
    const auto maskedSeed = xorBytes(seed, seedMask);

    std::vector<std::byte> encodedMessage;
    encodedMessage.reserve(encodedLength);
    encodedMessage.push_back(std::byte{0});
    encodedMessage.insert(encodedMessage.end(), maskedSeed.begin(), maskedSeed.end());
    encodedMessage.insert(
        encodedMessage.end(), maskedDataBlock.begin(), maskedDataBlock.end());
    return encodedMessage;
}

std::vector<std::byte> OaepCodec::decode(
    std::span<const std::byte> encodedMessage)
{
    constexpr std::size_t hashLength = hash::Sha256::DigestSize;
    constexpr std::size_t minimumEncodedLength = 2U * hashLength + 2U;

    if (encodedMessage.size() < minimumEncodedLength) {
        decodingFailed();
    }

    bool valid = encodedMessage[0] == std::byte{0};
    const auto maskedSeed = encodedMessage.subspan(1U, hashLength);
    const auto maskedDataBlock = encodedMessage.subspan(1U + hashLength);

    const auto seedMask = mgf::Mgf1::generate(maskedDataBlock, hashLength);
    const auto seed = xorBytes(maskedSeed, seedMask);
    const auto dataBlockMask = mgf::Mgf1::generate(seed, maskedDataBlock.size());
    const auto dataBlock = xorBytes(maskedDataBlock, dataBlockMask);

    const auto labelHash = hash::Sha256::digest(emptyLabel());
    valid = std::equal(labelHash.begin(), labelHash.end(), dataBlock.begin()) && valid;

    std::size_t delimiterIndex = dataBlock.size();
    for (std::size_t index = hashLength; index < dataBlock.size(); ++index) {
        if (dataBlock[index] == std::byte{0}) {
            continue;
        }
        if (dataBlock[index] == std::byte{1}) {
            delimiterIndex = index;
        } else {
            valid = false;
        }
        break;
    }

    if (delimiterIndex == dataBlock.size()) {
        valid = false;
    }
    if (!valid) {
        decodingFailed();
    }

    return std::vector<std::byte>(
        dataBlock.begin() + static_cast<std::ptrdiff_t>(delimiterIndex + 1U),
        dataBlock.end());
}

} // namespace stegowav::crypto::oaep
