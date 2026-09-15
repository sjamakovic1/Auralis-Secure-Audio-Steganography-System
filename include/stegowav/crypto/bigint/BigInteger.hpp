#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace stegowav::crypto::bigint {

class BigInteger {
public:
    BigInteger();
    BigInteger(std::uint64_t value);

    [[nodiscard]] static BigInteger fromBytes(std::span<const std::byte> bytes);
    [[nodiscard]] std::vector<std::byte> toBytes() const;

    [[nodiscard]] bool operator==(const BigInteger& rhs) const noexcept;
    [[nodiscard]] bool operator!=(const BigInteger& rhs) const noexcept;
    [[nodiscard]] bool operator<(const BigInteger& rhs) const noexcept;
    [[nodiscard]] bool operator<=(const BigInteger& rhs) const noexcept;
    [[nodiscard]] bool operator>(const BigInteger& rhs) const noexcept;
    [[nodiscard]] bool operator>=(const BigInteger& rhs) const noexcept;

    [[nodiscard]] BigInteger operator+(const BigInteger& rhs) const;
    BigInteger& operator+=(const BigInteger& rhs);

    [[nodiscard]] BigInteger operator-(const BigInteger& rhs) const;
    BigInteger& operator-=(const BigInteger& rhs);

    [[nodiscard]] BigInteger operator*(const BigInteger& rhs) const;

    [[nodiscard]] BigInteger operator/(const BigInteger& rhs) const;
    [[nodiscard]] BigInteger operator%(const BigInteger& rhs) const;
    BigInteger& operator/=(const BigInteger& rhs);
    BigInteger& operator%=(const BigInteger& rhs);

    [[nodiscard]] std::pair<BigInteger, BigInteger> divMod(
        const BigInteger& divisor) const;

    [[nodiscard]] static BigInteger gcd(BigInteger a, BigInteger b);
    [[nodiscard]] static BigInteger modPow(
        BigInteger base, BigInteger exponent, const BigInteger& modulus);
    [[nodiscard]] static BigInteger modInverse(
        const BigInteger& value, const BigInteger& modulus);

    [[nodiscard]] BigInteger operator<<(std::size_t bits) const;
    [[nodiscard]] BigInteger operator>>(std::size_t bits) const;

    [[nodiscard]] std::size_t bitLength() const noexcept;
    [[nodiscard]] bool bit(std::size_t index) const noexcept;
    [[nodiscard]] bool isZero() const noexcept;
    [[nodiscard]] bool isOdd() const noexcept;
    [[nodiscard]] std::size_t limbCount() const noexcept;
    [[nodiscard]] std::uint32_t moduloSmall(std::uint32_t divisor) const;

private:
    void normalize();
    void setBit(std::size_t index);

    std::vector<std::uint32_t> limbs_;
};

} // namespace stegowav::crypto::bigint
