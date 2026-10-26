#ifndef UNTHEMIDATOR_MEMORY_MANAGER_HPP
#define UNTHEMIDATOR_MEMORY_MANAGER_HPP

#include "c_memory.hpp"

class c_memory_manager final : public c_memory {
public:
    explicit c_memory_manager(const std::shared_ptr<c_pe_image>& pe_image);

    uint64_t allocate_helper_stub(uint32_t size);
    bool free_region(uint64_t address);
    [[nodiscard]] uint64_t get_region_size(uint64_t address) const;
    void write_memory(uint64_t address, const std::vector<uint8_t>& dump);

    void add_const_region(uint64_t start, uint64_t end);
    void tag_region(uint64_t address, const std::string& tag);
};

#endif //UNTHEMIDATOR_MEMORY_MANAGER_HPP
