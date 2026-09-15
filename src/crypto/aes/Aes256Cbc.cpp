#include "stegowav/crypto/aes/Aes256Cbc.hpp"

#include "stegowav/crypto/padding/Pkcs7.hpp"
#include "stegowav/crypto/random/SecureRandom.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace stegowav::crypto::aes {
namespace {

Aes256::Block readBlock(std::span<const std::byte> data, std::size_t offset)
{
    Aes256::Block block{};
    std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(offset),
                Aes256::BlockSize, block.begin());
    return block;
}

Aes256::Block xorBlocks(
    const Aes256::Block& left, const Aes256::Block& right) noexcept
{
    Aes256::Block result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = left[index] ^ right[index];
    }
    return result;
}

void appendBlock(std::vector<std::byte>& output, const Aes256::Block& block)
{
    output.insert(output.end(), block.begin(), block.end());
}

} // namespace

Aes256CbcEncryptedData Aes256Cbc::encrypt(
    std::span<const std::byte> plaintext,
    const Aes256::Key& key)
{
    const std::vector<std::byte> padded = padding::Pkcs7::pad(
        plaintext, Aes256::BlockSize);
    const std::vector<std::byte> randomIv = random::SecureRandom::bytes(
        Aes256::BlockSize);

    Aes256::Block iv{};
    std::copy(randomIv.begin(), randomIv.end(), iv.begin());

    const Aes256 aes(key);
    std::vector<std::byte> ciphertext;
    ciphertext.reserve(padded.size());
    Aes256::Block previousBlock = iv;

    for (std::size_t offset = 0; offset < padded.size(); offset += Aes256::BlockSize) {
        const Aes256::Block plaintextBlock = readBlock(padded, offset);
        const Aes256::Block encryptedBlock = aes.encryptBlock(
            xorBlocks(plaintextBlock, previousBlock));
        appendBlock(ciphertext, encryptedBlock);
        previousBlock = encryptedBlock;
    }

    return Aes256CbcEncryptedData{iv, std::move(ciphertext)};
}

std::vector<std::byte> Aes256Cbc::decrypt(
    std::span<const std::byte> ciphertext,
    const Aes256::Key& key,
    const Aes256::Block& iv)
{
    if (ciphertext.empty() || ciphertext.size() % Aes256::BlockSize != 0) {
        throw std::invalid_argument(
            "AES-CBC ciphertext must be non-empty and block-aligned.");
    }

    const Aes256 aes(key);
    std::vector<std::byte> paddedPlaintext;
    paddedPlaintext.reserve(ciphertext.size());
    Aes256::Block previousBlock = iv;

    for (std::size_t offset = 0; offset < ciphertext.size(); offset += Aes256::BlockSize) {
        const Aes256::Block ciphertextBlock = readBlock(ciphertext, offset);
        const Aes256::Block plaintextBlock = xorBlocks(
            aes.decryptBlock(ciphertextBlock), previousBlock);
        appendBlock(paddedPlaintext, plaintextBlock);
        previousBlock = ciphertextBlock;
    }

    return padding::Pkcs7::unpad(paddedPlaintext, Aes256::BlockSize);
}

} // namespace stegowav::crypto::aes
