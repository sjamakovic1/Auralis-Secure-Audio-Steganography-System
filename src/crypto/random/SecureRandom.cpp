#include "stegowav/crypto/random/SecureRandom.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

namespace stegowav::crypto::random {

std::vector<std::byte> SecureRandom::bytes(std::size_t count)
{
    std::vector<std::byte> result(count);
    fill(result);
    return result;
}

void SecureRandom::fill(std::span<std::byte> buffer)
{
    if (buffer.empty()) {
        return;
    }

#ifdef _WIN32
    std::size_t offset = 0;
    while (offset < buffer.size()) {
        const std::size_t remaining = buffer.size() - offset;
        const std::size_t chunkSize = std::min(
            remaining,
            static_cast<std::size_t>(std::numeric_limits<ULONG>::max()));

        const NTSTATUS status = BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(buffer.data() + offset),
            static_cast<ULONG>(chunkSize),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (status < 0) {
            throw std::runtime_error(
                "BCryptGenRandom failed with NTSTATUS "
                + std::to_string(static_cast<long>(status)) + ".");
        }
        offset += chunkSize;
    }
#else
    throw std::runtime_error(
        "SecureRandom requires the Windows BCrypt system RNG on this build.");
#endif
}

} // namespace stegowav::crypto::random
