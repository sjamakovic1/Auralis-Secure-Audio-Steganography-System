#pragma once

#include <cstddef>
#include <utility>
#include <vector>

namespace stegowav::payload {

class Payload {
public:
    Payload() = default;
    explicit Payload(std::vector<std::byte> data)
        : data_(std::move(data))
    {
    }

    ~Payload() = default;

    [[nodiscard]] const std::vector<std::byte>& data() const noexcept
    {
        return data_;
    }

    [[nodiscard]] std::vector<std::byte>& data() noexcept
    {
        return data_;
    }

    [[nodiscard]] std::size_t size() const noexcept
    {
        return data_.size();
    }

private:
    std::vector<std::byte> data_;
};

} // namespace stegowav::payload
