#pragma once

#include <array>
#include <cstddef>

namespace stegowav::crypto::aes {

class Aes256 {
public:
    static constexpr std::size_t BlockSize = 16;
    static constexpr std::size_t KeySize = 32;
    static constexpr std::size_t Rounds = 14;

    using Block = std::array<std::byte, BlockSize>;
    using Key = std::array<std::byte, KeySize>;

    explicit Aes256(const Key& key);

    [[nodiscard]] Block encryptBlock(const Block& plaintext) const;
    [[nodiscard]] Block decryptBlock(const Block& ciphertext) const;

private:
    std::array<Block, Rounds + 1U> roundKeys_{};
};

} // namespace stegowav::crypto::aes
