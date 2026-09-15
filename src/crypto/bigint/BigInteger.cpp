#include "stegowav/crypto/bigint/BigInteger.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace stegowav::crypto::bigint {
namespace {

constexpr std::size_t LimbBits = 32;
constexpr std::uint64_t LimbMask = std::numeric_limits<std::uint32_t>::max();

} // namespace

BigInteger::BigInteger()
    : limbs_{0}
{
}

BigInteger::BigInteger(std::uint64_t value)
    : limbs_{static_cast<std::uint32_t>(value & LimbMask)}
{
    const auto high = static_cast<std::uint32_t>(value >> LimbBits);
    if (high != 0) {
        limbs_.push_back(high);
    }
}

BigInteger BigInteger::fromBytes(std::span<const std::byte> bytes)
{
    BigInteger result;
    result.limbs_.assign(std::max<std::size_t>(1, (bytes.size() + 3U) / 4U), 0);

    for (std::size_t offset = 0; offset < bytes.size(); ++offset) {
        const std::size_t byteIndex = bytes.size() - 1U - offset;
        const std::size_t limbIndex = offset / 4U;
        const std::size_t shift = (offset % 4U) * 8U;
        result.limbs_[limbIndex] |=
            static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[byteIndex]))
            << shift;
    }

    result.normalize();
    return result;
}

std::vector<std::byte> BigInteger::toBytes() const
{
    if (isZero()) {
        return {std::byte{0}};
    }

    const std::size_t byteCount = (bitLength() + 7U) / 8U;
    std::vector<std::byte> bytes(byteCount);
    for (std::size_t offset = 0; offset < byteCount; ++offset) {
        const std::size_t limbIndex = offset / 4U;
        const std::size_t shift = (offset % 4U) * 8U;
        const auto value = static_cast<std::uint8_t>(limbs_[limbIndex] >> shift);
        bytes[byteCount - 1U - offset] = static_cast<std::byte>(value);
    }
    return bytes;
}

bool BigInteger::operator==(const BigInteger& rhs) const noexcept
{
    return limbs_ == rhs.limbs_;
}

bool BigInteger::operator!=(const BigInteger& rhs) const noexcept
{
    return !(*this == rhs);
}

bool BigInteger::operator<(const BigInteger& rhs) const noexcept
{
    if (limbs_.size() != rhs.limbs_.size()) {
        return limbs_.size() < rhs.limbs_.size();
    }

    for (std::size_t index = limbs_.size(); index-- > 0;) {
        if (limbs_[index] != rhs.limbs_[index]) {
            return limbs_[index] < rhs.limbs_[index];
        }
    }
    return false;
}

bool BigInteger::operator<=(const BigInteger& rhs) const noexcept
{
    return !(rhs < *this);
}

bool BigInteger::operator>(const BigInteger& rhs) const noexcept
{
    return rhs < *this;
}

bool BigInteger::operator>=(const BigInteger& rhs) const noexcept
{
    return !(*this < rhs);
}

BigInteger BigInteger::operator+(const BigInteger& rhs) const
{
    BigInteger result = *this;
    result += rhs;
    return result;
}

BigInteger& BigInteger::operator+=(const BigInteger& rhs)
{
    const std::size_t resultSize = std::max(limbs_.size(), rhs.limbs_.size());
    limbs_.resize(resultSize, 0);

    std::uint64_t carry = 0;
    for (std::size_t index = 0; index < resultSize; ++index) {
        const std::uint64_t right = index < rhs.limbs_.size() ? rhs.limbs_[index] : 0;
        const std::uint64_t sum = static_cast<std::uint64_t>(limbs_[index]) + right + carry;
        limbs_[index] = static_cast<std::uint32_t>(sum & LimbMask);
        carry = sum >> LimbBits;
    }
    if (carry != 0) {
        limbs_.push_back(static_cast<std::uint32_t>(carry));
    }
    return *this;
}

BigInteger BigInteger::operator-(const BigInteger& rhs) const
{
    BigInteger result = *this;
    result -= rhs;
    return result;
}

BigInteger& BigInteger::operator-=(const BigInteger& rhs)
{
    if (*this < rhs) {
        throw std::underflow_error("BigInteger subtraction would produce a negative value.");
    }

    std::uint64_t borrow = 0;
    for (std::size_t index = 0; index < limbs_.size(); ++index) {
        const std::uint64_t right =
            (index < rhs.limbs_.size() ? rhs.limbs_[index] : 0) + borrow;
        const std::uint64_t left = limbs_[index];
        limbs_[index] = static_cast<std::uint32_t>(left - right);
        borrow = left < right ? 1U : 0U;
    }

    normalize();
    return *this;
}

BigInteger BigInteger::operator*(const BigInteger& rhs) const
{
    if (isZero() || rhs.isZero()) {
        return BigInteger{};
    }

    BigInteger result;
    result.limbs_.assign(limbs_.size() + rhs.limbs_.size(), 0);

    for (std::size_t leftIndex = 0; leftIndex < limbs_.size(); ++leftIndex) {
        std::uint64_t carry = 0;
        for (std::size_t rightIndex = 0; rightIndex < rhs.limbs_.size(); ++rightIndex) {
            const std::size_t resultIndex = leftIndex + rightIndex;
            const std::uint64_t product =
                static_cast<std::uint64_t>(limbs_[leftIndex]) * rhs.limbs_[rightIndex]
                + result.limbs_[resultIndex] + carry;
            result.limbs_[resultIndex] = static_cast<std::uint32_t>(product & LimbMask);
            carry = product >> LimbBits;
        }
        result.limbs_[leftIndex + rhs.limbs_.size()] = static_cast<std::uint32_t>(carry);
    }

    result.normalize();
    return result;
}

BigInteger BigInteger::operator/(const BigInteger& rhs) const
{
    return divMod(rhs).first;
}

BigInteger BigInteger::operator%(const BigInteger& rhs) const
{
    return divMod(rhs).second;
}

BigInteger& BigInteger::operator/=(const BigInteger& rhs)
{
    *this = divMod(rhs).first;
    return *this;
}

BigInteger& BigInteger::operator%=(const BigInteger& rhs)
{
    *this = divMod(rhs).second;
    return *this;
}

std::pair<BigInteger, BigInteger> BigInteger::divMod(
    const BigInteger& divisor) const
{
    if (divisor.isZero()) {
        throw std::domain_error("BigInteger division by zero.");
    }
    if (isZero()) {
        return {BigInteger{}, BigInteger{}};
    }
    if (*this < divisor) {
        return {BigInteger{}, *this};
    }
    if (*this == divisor) {
        return {BigInteger{1}, BigInteger{}};
    }
    if (divisor == BigInteger{1}) {
        return {*this, BigInteger{}};
    }

    BigInteger quotient;
    BigInteger remainder;

    for (std::size_t bitIndex = bitLength(); bitIndex-- > 0;) {
        remainder = remainder << 1U;
        if (bit(bitIndex)) {
            remainder += BigInteger{1};
        }
        if (remainder >= divisor) {
            remainder -= divisor;
            quotient.setBit(bitIndex);
        }
    }

    quotient.normalize();
    remainder.normalize();
    return {std::move(quotient), std::move(remainder)};
}

BigInteger BigInteger::gcd(BigInteger a, BigInteger b)
{
    while (!b.isZero()) {
        BigInteger remainder = a % b;
        a = std::move(b);
        b = std::move(remainder);
    }
    return a;
}

BigInteger BigInteger::modPow(
    BigInteger base, BigInteger exponent, const BigInteger& modulus)
{
    if (modulus.isZero()) {
        throw std::domain_error("BigInteger modular exponentiation with zero modulus.");
    }
    if (modulus == BigInteger{1}) {
        return BigInteger{};
    }
    if (exponent.isZero()) {
        return BigInteger{1};
    }

    if (!modulus.isOdd()) {
        BigInteger result{1};
        if (base >= modulus) {
            base %= modulus;
        }

        while (!exponent.isZero()) {
            if (exponent.isOdd()) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1U;
            if (!exponent.isZero()) {
                base = (base * base) % modulus;
            }
        }
        return result;
    }

    const std::size_t limbCount = modulus.limbs_.size();
    if (limbCount > std::numeric_limits<std::size_t>::max() / (2U * LimbBits)) {
        throw std::overflow_error("Montgomery radix bit length is too large.");
    }

    std::uint32_t inverse = 1;
    for (std::size_t iteration = 0; iteration < 5; ++iteration) {
        inverse *= 2U - modulus.limbs_[0] * inverse;
    }
    const std::uint32_t n0Prime = 0U - inverse;

    std::vector<std::uint32_t> scratch(2U * limbCount + 2U, 0);
    const auto montgomeryMultiply = [&](const BigInteger& left,
                                        const BigInteger& right) {
        std::fill(scratch.begin(), scratch.end(), 0);

        for (std::size_t leftIndex = 0; leftIndex < limbCount; ++leftIndex) {
            const std::uint64_t leftLimb =
                leftIndex < left.limbs_.size() ? left.limbs_[leftIndex] : 0;
            std::uint64_t carry = 0;

            for (std::size_t rightIndex = 0; rightIndex < limbCount; ++rightIndex) {
                const std::uint64_t rightLimb =
                    rightIndex < right.limbs_.size() ? right.limbs_[rightIndex] : 0;
                const std::size_t resultIndex = leftIndex + rightIndex;
                const std::uint64_t product = leftLimb * rightLimb
                    + scratch[resultIndex] + carry;
                scratch[resultIndex] = static_cast<std::uint32_t>(product);
                carry = product >> LimbBits;
            }

            std::size_t carryIndex = leftIndex + limbCount;
            while (carry != 0) {
                const std::uint64_t sum = scratch[carryIndex] + carry;
                scratch[carryIndex] = static_cast<std::uint32_t>(sum);
                carry = sum >> LimbBits;
                ++carryIndex;
            }
        }

        for (std::size_t index = 0; index < limbCount; ++index) {
            const std::uint32_t multiplier =
                static_cast<std::uint32_t>(
                    static_cast<std::uint64_t>(scratch[index]) * n0Prime);
            std::uint64_t carry = 0;

            for (std::size_t modulusIndex = 0;
                 modulusIndex < limbCount;
                 ++modulusIndex) {
                const std::size_t resultIndex = index + modulusIndex;
                const std::uint64_t sum =
                    static_cast<std::uint64_t>(multiplier)
                        * modulus.limbs_[modulusIndex]
                    + scratch[resultIndex] + carry;
                scratch[resultIndex] = static_cast<std::uint32_t>(sum);
                carry = sum >> LimbBits;
            }

            std::size_t carryIndex = index + limbCount;
            while (carry != 0) {
                const std::uint64_t sum = scratch[carryIndex] + carry;
                scratch[carryIndex] = static_cast<std::uint32_t>(sum);
                carry = sum >> LimbBits;
                ++carryIndex;
            }
        }

        BigInteger reduced;
        reduced.limbs_.assign(
            scratch.begin() + static_cast<std::ptrdiff_t>(limbCount),
            scratch.end());
        reduced.normalize();
        if (reduced >= modulus) {
            reduced -= modulus;
        }
        return reduced;
    };

    if (base >= modulus) {
        base %= modulus;
    }

    const std::size_t radixSquaredBits = 2U * limbCount * LimbBits;
    const BigInteger radixSquared = (BigInteger{1} << radixSquaredBits) % modulus;
    BigInteger result = montgomeryMultiply(BigInteger{1}, radixSquared);
    BigInteger baseMontgomery = montgomeryMultiply(base, radixSquared);

    while (!exponent.isZero()) {
        if (exponent.isOdd()) {
            result = montgomeryMultiply(result, baseMontgomery);
        }
        exponent = exponent >> 1U;
        if (!exponent.isZero()) {
            baseMontgomery = montgomeryMultiply(baseMontgomery, baseMontgomery);
        }
    }

    return montgomeryMultiply(result, BigInteger{1});
}

BigInteger BigInteger::modInverse(
    const BigInteger& value, const BigInteger& modulus)
{
    if (modulus.isZero()) {
        throw std::domain_error("BigInteger modular inverse with zero modulus.");
    }
    if (modulus == BigInteger{1}) {
        throw std::domain_error("Modular inverse is not defined for modulus one.");
    }

    BigInteger r = modulus;
    BigInteger newR = value % modulus;
    BigInteger t;
    BigInteger newT{1};

    while (!newR.isZero()) {
        const BigInteger quotient = r / newR;
        const BigInteger nextR = r - quotient * newR;
        const BigInteger quotientNewT = (quotient * newT) % modulus;
        const BigInteger nextT = t >= quotientNewT
            ? t - quotientNewT
            : modulus - (quotientNewT - t);

        r = std::move(newR);
        newR = nextR;
        t = std::move(newT);
        newT = nextT;
    }

    if (r != BigInteger{1}) {
        throw std::domain_error("Modular inverse does not exist.");
    }

    return t % modulus;
}

BigInteger BigInteger::operator<<(std::size_t bits) const
{
    if (isZero() || bits == 0) {
        return *this;
    }

    const std::size_t limbShift = bits / LimbBits;
    const std::size_t bitShift = bits % LimbBits;
    BigInteger result;
    result.limbs_.assign(limbs_.size() + limbShift + (bitShift != 0 ? 1U : 0U), 0);

    std::uint64_t carry = 0;
    for (std::size_t index = 0; index < limbs_.size(); ++index) {
        const std::uint64_t shifted =
            (static_cast<std::uint64_t>(limbs_[index]) << bitShift) | carry;
        result.limbs_[index + limbShift] = static_cast<std::uint32_t>(shifted & LimbMask);
        carry = shifted >> LimbBits;
    }
    if (bitShift != 0) {
        result.limbs_[limbs_.size() + limbShift] = static_cast<std::uint32_t>(carry);
    }

    result.normalize();
    return result;
}

BigInteger BigInteger::operator>>(std::size_t bits) const
{
    if (bits == 0) {
        return *this;
    }

    const std::size_t limbShift = bits / LimbBits;
    const std::size_t bitShift = bits % LimbBits;
    if (limbShift >= limbs_.size()) {
        return BigInteger{};
    }

    BigInteger result;
    result.limbs_.assign(limbs_.size() - limbShift, 0);

    std::uint32_t carry = 0;
    for (std::size_t sourceIndex = limbs_.size(); sourceIndex-- > limbShift;) {
        const std::uint32_t limb = limbs_[sourceIndex];
        const std::size_t destinationIndex = sourceIndex - limbShift;
        if (bitShift == 0) {
            result.limbs_[destinationIndex] = limb;
        } else {
            result.limbs_[destinationIndex] = (limb >> bitShift) | carry;
            carry = limb << (LimbBits - bitShift);
        }
    }

    result.normalize();
    return result;
}

std::size_t BigInteger::bitLength() const noexcept
{
    if (isZero()) {
        return 0;
    }
    return (limbs_.size() - 1U) * LimbBits + std::bit_width(limbs_.back());
}

bool BigInteger::bit(std::size_t index) const noexcept
{
    const std::size_t limbIndex = index / LimbBits;
    if (limbIndex >= limbs_.size()) {
        return false;
    }
    return ((limbs_[limbIndex] >> (index % LimbBits)) & 1U) != 0;
}

bool BigInteger::isZero() const noexcept
{
    return limbs_.size() == 1 && limbs_[0] == 0;
}

bool BigInteger::isOdd() const noexcept
{
    return (limbs_[0] & 1U) != 0;
}

std::size_t BigInteger::limbCount() const noexcept
{
    return limbs_.size();
}

std::uint32_t BigInteger::moduloSmall(std::uint32_t divisor) const
{
    if (divisor == 0) {
        throw std::domain_error("BigInteger modulo by zero.");
    }

    std::uint64_t remainder = 0;
    for (std::size_t index = limbs_.size(); index-- > 0;) {
        const std::uint64_t combined =
            (remainder << LimbBits) | limbs_[index];
        remainder = combined % divisor;
    }
    return static_cast<std::uint32_t>(remainder);
}

void BigInteger::normalize()
{
    while (limbs_.size() > 1 && limbs_.back() == 0) {
        limbs_.pop_back();
    }
    if (limbs_.empty()) {
        limbs_.push_back(0);
    }
}

void BigInteger::setBit(std::size_t index)
{
    const std::size_t limbIndex = index / LimbBits;
    if (limbIndex >= limbs_.size()) {
        limbs_.resize(limbIndex + 1U, 0);
    }
    limbs_[limbIndex] |= std::uint32_t{1} << (index % LimbBits);
}

} // namespace stegowav::crypto::bigint
