#pragma once

#include <array>
#include <cstddef>
#include <vector>

namespace stegowav::wav {

struct RiffChunk {
    std::array<char, 4> id{};
    std::vector<std::byte> data;
};

} // namespace stegowav::wav
