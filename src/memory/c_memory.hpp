#ifndef UNTHEMIDATOR_BIN_LAYOUT_HPP
#define UNTHEMIDATOR_BIN_LAYOUT_HPP

#include <unordered_map>
#include <map>
#include <vector>
#include <optional>
#include <memory>
#include <string>
#include <chrono>

#include "kuser_shared_data.hpp"

class c_pe_image;

inline uint64_t page_up(const uint64_t address, const uint64_t page_size) {
    return (address + page_size - 0x1) & ~(page_size - 0x1);
}

class c_memory {
public:
    static constexpr uint64_t k_shared_data_base = 0x7FFE0000;
    static constexpr uint32_t k_shared_data_size = 0x1000;

    [[nodiscard]] static bool overlaps_shared_data(uint64_t address, uint64_t size);
    [[nodiscard]] const unthemidator::windows::s_kuser_shared_data& get_shared_data() const;

    explicit c_memory(const std::shared_ptr<c_pe_image>& pe_image);

    [[nodiscard]] const std::vector<uint8_t>& get_mapped_image() const;
    [[nodiscard]] std::shared_ptr<c_pe_image> get_pe_image() const;

    [[nodiscard]] uint64_t get_image_base() const;
    [[nodiscard]] uint32_t get_image_size() const;

    [[nodiscard]] uint64_t get_stack_base() const;
    [[nodiscard]] uint32_t get_stack_size() const;
    [[nodiscard]] uint64_t get_initial_stack_pointer() const;
    [[nodiscard]] uint32_t get_stack_reserve_size() const;

    [[nodiscard]] uint64_t get_committed_memory_start() const;
    [[nodiscard]] uint64_t get_memory_end() const;

    [[nodiscard]] bool is_in_const_region(uint64_t address, uint8_t size) const;

    bool read_executable_byte(uint64_t address, uint8_t* byte) const;

    [[nodiscard]] std::optional<std::string> get_address_tag(uint64_t address) const;
    [[nodiscard]] std::optional<uint64_t> get_address_by_tag(std::string_view tag) const;

    template<typename T>
    bool read_image_mem(const uint64_t address, const uint8_t size, T* target, const bool ignore_rw = false) {
        if (!ignore_rw && !is_in_const_region(address, size)) {
            return false;
        }

        *target = *reinterpret_cast<const T*>(m_mapped_image.data() + address - m_image_base);
        return true;
    }
protected:
    mutable unthemidator::windows::s_kuser_shared_data m_shared_data{};
    const std::chrono::steady_clock::time_point m_clock_start = std::chrono::steady_clock::now();
    const std::chrono::system_clock::time_point m_system_time_start = std::chrono::system_clock::now();

    uint64_t m_image_base;
    uint32_t m_image_size;

    uint64_t m_stack_base;
    uint32_t m_stack_size;
    uint32_t m_stack_reserve;

    uint64_t m_commited_memory_start = 0;
    uint64_t m_cursor = 0;

    std::vector<uint8_t> m_mapped_image{};
    std::map<uint64_t, std::vector<uint8_t>> m_allocated_regions{};

    std::shared_ptr<c_pe_image> m_pe_image{};

    std::vector<std::pair<uint64_t, uint64_t>> m_const_regions{};

    std::unordered_map<uint64_t, std::vector<std::string>> m_tagged_regions{};
};

#endif //UNTHEMIDATOR_BIN_LAYOUT_HPP
