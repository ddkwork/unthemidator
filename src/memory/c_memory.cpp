#include "c_memory.hpp"

#include <stdexcept>
#include <algorithm>

#include "../pe/c_pe_image.hpp"

constexpr uint32_t stack_size = 0x50000;
constexpr uint64_t page_size = 0x1000;
constexpr uint32_t stack_reserve = 0x10000;

c_memory::c_memory(const std::shared_ptr<c_pe_image>& pe_image) : m_pe_image(pe_image) {
    m_mapped_image = m_pe_image->get_mapped_image();

    m_image_base = m_pe_image->get_image_base();
    m_image_size = static_cast<uint32_t>(m_mapped_image.size());

    if (overlaps_shared_data(m_image_base, m_image_size)) {
        throw std::runtime_error("memory: image overlaps KUSER_SHARED_DATA");
    }

    m_stack_reserve = stack_reserve;
    m_stack_size = stack_size;

    uint64_t memory_end;

    // decide whether the stack region should be above the mapped image region or below it
    if (m_image_base <= m_stack_size + 0x4000) {
        m_stack_base = page_up(m_image_base + m_image_size + 0x3000, page_size);
        memory_end = page_up(m_stack_base + m_stack_size + 0x1000, page_size);
    } else {
        m_stack_base = page_up(m_image_base - m_stack_size - 0x3000, page_size);
        memory_end = page_up(m_image_base + m_image_size + 0x1000, page_size);
    }

    if (overlaps_shared_data(m_stack_base, m_stack_size)) {
        m_stack_base = page_up(std::max(m_image_base + m_image_size,
            k_shared_data_base + k_shared_data_size) + 0x3000, page_size);
        memory_end = m_stack_base + m_stack_size + 0x1000;
    }

    m_cursor = page_up(memory_end + 0x1000, page_size);
    if (overlaps_shared_data(m_cursor, 1)) {
        m_cursor = k_shared_data_base + k_shared_data_size;
    }

    if (!pe_image->is_x64() && m_cursor > UINT32_MAX) {
        throw std::runtime_error("memory: x86 image exceeds 32-bit address space");
    }

    m_commited_memory_start = m_cursor;
    m_tagged_regions[k_shared_data_base] = { "KUSER_SHARED_DATA" };

    auto& data = m_shared_data;
    data.tick_count_multiplier = 0x0FA00000; // 15.625 ms, scaled by 2^24.
    data.image_number_low = 0x14C;
    data.image_number_high = 0x8664;
    constexpr char16_t system_root[] = u"C:\\Windows";
    std::copy(std::begin(system_root), std::end(system_root), data.nt_system_root);
    data.large_page_minimum = 0x200000;
    data.rng_seed_version = 1;
    data.nt_build_number = 26100;
    data.nt_product_type = 1; // NtProductWinNt (workstation).
    data.product_type_is_valid = 1;
    data.native_processor_architecture = 9; // AMD64, also for WOW64 guests.
    data.nt_major_version = 10;

    // Features exposed by the emulator's CPUID leaf 1, plus OS facilities.
    for (const auto feature : { 2, 3, 6, 8, 9, 10, 11, 12, 13, 14, 15, 17, 23, 28, 36, 37, 38, 39 }) {
        data.processor_features[feature] = 1;
    }
    data.boot_id = 1;
    data.suite_mask = 0x100; // Single-user terminal services.
    data.mitigation_policies = 1; // NX opt-in; no kernel debugger or safe boot.
    data.cycles_per_yield = 64;
    data.active_console_id = 1;
    data.com_plus_package = 1;
    data.last_system_rit_event_tick_count = 86'399'000;
    data.number_of_physical_pages = 0x400000; // 16 GiB.
    data.full_number_of_physical_pages = data.number_of_physical_pages;
    data.test_ret_instruction = 0xC3;
    data.qpc_frequency = 10'000'000;
    data.cookie = 0xA7C35E19;
    data.console_session_foreground_process_id = 0x1000;
    data.qpc_system_time_increment = data.qpc_interrupt_time_increment = 1ULL << 32;
    data.qpc_system_time_increment_shift = data.qpc_interrupt_time_increment_shift = 32;
    data.unparked_processor_count = data.active_processor_count = 8;
    data.active_group_count = 1;
    data.lang_generation_count = 1;
    // QPC bypass stays disabled: the synthetic 10 MHz clock is not the host TSC.
    data.xstate.enabled_features = data.xstate.enabled_volatile_features = 7; // x87/SSE/AVX.
    data.xstate.size = data.xstate.all_feature_size = data.xstate.all_non_large_feature_size = 832;
    data.xstate.features[0] = { 0, 160 };
    data.xstate.features[1] = { 160, 256 };
    data.xstate.features[2] = { 576, 256 };
    data.xstate.all_features[0] = 160;
    data.xstate.all_features[1] = data.xstate.all_features[2] = 256;
}

const unthemidator::windows::s_kuser_shared_data& c_memory::get_shared_data() const {
    using namespace std::chrono;
    using ticks = duration<uint64_t, std::ratio<1, 10'000'000>>;
    const auto elapsed = steady_clock::now() - m_clock_start;
    const auto uptime = duration_cast<ticks>(hours(24) + elapsed).count();
    // Convert separately: a nanosecond system_clock cannot span 1601 to today.
    const auto epoch_bias = duration_cast<ticks>(sys_days{1970y / January / 1} - sys_days{1601y / January / 1});
    const auto time = (epoch_bias + duration_cast<ticks>(m_system_time_start.time_since_epoch()) +
        duration_cast<ticks>(elapsed)).count();
    const auto system_time = [](const uint64_t value) {
        const auto high = static_cast<int32_t>(value >> 32);
        return unthemidator::windows::s_ksystem_time{ static_cast<uint32_t>(value), high, high };
    };

    // Read-only to the guest, but deliberately not an optimizer constant.
    m_shared_data.interrupt_time = system_time(uptime);
    m_shared_data.system_time = system_time(time);
    m_shared_data.tick_count = system_time(uptime / 156'250);
    m_shared_data.baseline_system_time_qpc = m_shared_data.baseline_interrupt_time_qpc = uptime;
    return m_shared_data;
}

bool c_memory::overlaps_shared_data(const uint64_t address, const uint64_t size) {
    return size && address < k_shared_data_base + k_shared_data_size &&
        (address >= k_shared_data_base || size > k_shared_data_base - address);
}

const std::vector<uint8_t>& c_memory::get_mapped_image() const {
    return m_mapped_image;
}

std::shared_ptr<c_pe_image> c_memory::get_pe_image() const {
    return m_pe_image;
}

uint64_t c_memory::get_image_base() const {
    return m_image_base;
}

uint32_t c_memory::get_image_size() const {
    return m_image_size;
}

uint64_t c_memory::get_stack_base() const {
    return m_stack_base;
}

uint32_t c_memory::get_stack_size() const {
    return m_stack_size;
}

uint64_t c_memory::get_initial_stack_pointer() const {
    return m_stack_base + m_stack_size - m_stack_reserve;
}

uint32_t c_memory::get_stack_reserve_size() const {
    return m_stack_reserve;
}

uint64_t c_memory::get_committed_memory_start() const {
    return m_commited_memory_start;
}

uint64_t c_memory::get_memory_end() const {
    return m_cursor;
}

bool c_memory::is_in_const_region(const uint64_t address, const uint8_t size) const {
    if (address < m_image_base || address + size >= m_image_base + m_image_size) {
        return false;
    }

    bool is_in_const_region = false;

    for (const auto [start, end] : m_const_regions) {
        if (address >= start && address < end) {
            is_in_const_region = true;
            break;
        }
    }

    return is_in_const_region;
}

bool c_memory::read_executable_byte(const uint64_t address, uint8_t *byte) const {
    if (overlaps_shared_data(address, 1)) {
        return false;
    }

    if (address >= m_image_base && address < m_image_base + m_image_size) {
        *byte = m_mapped_image.at(address - m_image_base);
        return true;
    }

    if (auto region = m_allocated_regions.upper_bound(address); region != m_allocated_regions.begin()) {
        --region;
        if (address - region->first < region->second.size()) {
            *byte = region->second.at(address - region->first);
            return true;
        }
    }

    return false;
}

std::optional<std::string> c_memory::get_address_tag(const uint64_t address) const {
    if (m_tagged_regions.contains(address)) {
        return { *m_tagged_regions.at(address).begin() };
    }

    return std::nullopt;
}

std::optional<uint64_t> c_memory::get_address_by_tag(std::string_view tag) const {
    const auto it = std::ranges::find_if(m_tagged_regions, [&](const auto& kv) {
        return std::ranges::find(kv.second, tag) != kv.second.end();
    });

    if (it == m_tagged_regions.end()) {
        return std::nullopt;
    }

    return it->first;
}
