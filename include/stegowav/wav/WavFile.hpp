#pragma once

#include "stegowav/wav/RiffChunk.hpp"
#include "stegowav/wav/WavFormat.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace stegowav::wav {

class WavFile {
public:
    WavFile() = default;
    WavFile(WavFormat format, std::vector<RiffChunk> chunks)
        : format_(format), chunks_(std::move(chunks))
    {
    }

    ~WavFile() = default;

    [[nodiscard]] const WavFormat& format() const noexcept
    {
        return format_;
    }

    [[nodiscard]] const std::vector<std::byte>& audioData() const
    {
        return dataChunk().data;
    }

    [[nodiscard]] std::vector<std::byte>& audioData()
    {
        return dataChunk().data;
    }

    [[nodiscard]] const std::vector<RiffChunk>& chunks() const noexcept
    {
        return chunks_;
    }

private:
    [[nodiscard]] const RiffChunk& dataChunk() const
    {
        const auto iterator = std::find_if(chunks_.begin(), chunks_.end(), [](const RiffChunk& chunk) {
            return std::string_view(chunk.id.data(), chunk.id.size()) == "data";
        });
        if (iterator == chunks_.end()) {
            throw std::logic_error("WavFile does not contain a data chunk.");
        }
        return *iterator;
    }

    [[nodiscard]] RiffChunk& dataChunk()
    {
        return const_cast<RiffChunk&>(std::as_const(*this).dataChunk());
    }

    WavFormat format_{};
    std::vector<RiffChunk> chunks_;
};

} // namespace stegowav::wav
