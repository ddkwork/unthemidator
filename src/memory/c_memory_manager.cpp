#include "c_memory_manager.hpp"

#include <stdexcept>
#include <algorithm>

#include "../pe/c_pe_image.hpp"

c_memory_manager::c_memory_manager(const std::shared_ptr<c_pe_image>& pe_image) : c_memory(pe_image) {
    //
}

uint64_t c_memory_manager::allocate_helper_stub(const uint32_t size) {
    const auto aligned_size = page_up(size ? size : 1, 0x1000);
    auto address = m_commited_memory_start;

    for (const auto &[base, region] : m_allocated_regions) {
        if (overlaps_shared_data(address, aligned_size)) {
            address = k_shared_data_base + k_shared_data_size;
        }

        if (address <= base && aligned_size <= base - address) {
            break;
        }

        address = std::max(address, base + region.size());
    }

    if (overlaps_shared_data(address, aligned_size)) {
        address = k_shared_data_base + k_shared_data_size;
    }

    if (address > UINT64_MAX - aligned_size ||
        (!m_pe_image->is_x64() && address + aligned_size > 0x100000000ULL)) {
        throw std::runtime_error("memory: allocation exceeds address space");
    }

    m_allocated_regions.emplace(address, std::vector<uint8_t>(aligned_size, 0));
    m_cursor = std::max(m_cursor, address + aligned_size);

    return address;
}

uint64_t c_memory_manager::get_region_size(const uint64_t address) const {
    const auto it = m_allocated_regions.find(address);
    return it == m_allocated_regions.end() ? 0 : it->second.size();
}

bool c_memory_manager::free_region(const uint64_t address) {
    const auto size = get_region_size(address);
    if (!size) {
        return false;
    }

    m_allocated_regions.erase(address);
    std::erase_if(m_tagged_regions, [&](const auto &entry) {
        return entry.first >= address && entry.first - address < size;
    });
    std::erase_if(m_const_regions, [&](const auto &region) {
        return region.first < address + size && region.second > address;
    });

    m_cursor = m_allocated_regions.empty() ? m_commited_memory_start :
        m_allocated_regions.rbegin()->first + m_allocated_regions.rbegin()->second.size();
    return true;
}

void c_memory_manager::write_memory(const uint64_t address, const std::vector<uint8_t> &dump) {
    if (overlaps_shared_data(address, dump.size())) {
        throw std::runtime_error("memory: KUSER_SHARED_DATA is read-only");
    }

    if (address > m_cursor || dump.size() > m_cursor - address) {
        throw std::runtime_error("memory: attempted out of range write");
    }

    if (address >= m_image_base && address < m_image_base + m_image_size) {
        if (dump.size() > m_mapped_image.size() - address + m_image_base) {
            throw std::runtime_error("memory: attempted out of range write");
        }

        memcpy(m_mapped_image.data() + address - m_image_base, dump.data(), dump.size());
        return;
    }

    auto region = m_allocated_regions.upper_bound(address);
    if (region != m_allocated_regions.begin()) {
        --region;
        const auto offset = address - region->first;
        if (offset <= region->second.size() && dump.size() <= region->second.size() - offset) {
            memcpy(region->second.data() + offset, dump.data(), dump.size());
            return;
        }
    }

    throw std::runtime_error("memory: attempted out of range write (2)");
}

void c_memory_manager::add_const_region(uint64_t start, uint64_t end) {
    m_const_regions.emplace_back(start, end);
}

void c_memory_manager::tag_region(uint64_t address, const std::string& tag) {
    if (!m_tagged_regions.contains(address)) {
        m_tagged_regions.emplace(address, std::vector<std::string>{});
    }

    m_tagged_regions.at(address).emplace_back(tag);
}
