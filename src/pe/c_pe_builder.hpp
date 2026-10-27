#ifndef UNTHEMIDATOR_C_PE_BUILDER_HPP
#define UNTHEMIDATOR_C_PE_BUILDER_HPP

#include <cstddef>
#include <memory>

#include "../unpacker/themida_structs.hpp"

class c_pe_image;
class c_memory_manager;
class c_emulator_ctx;

class c_pe_builder {
public:
    explicit c_pe_builder(const std::shared_ptr<c_pe_image> &pe_image, const std::shared_ptr<c_memory_manager> &memory_manager);

    void set_entry_rva(uint32_t offset);
    void set_imports(const std::vector<s_themida_recovered_import> &imports);

    void set_loader_shellcode(const std::vector<uint8_t> &shellcode);
    void set_tls_callbacks(const std::vector<uint64_t> &callbacks);

    void build(const c_emulator_ctx& ctx);

    [[nodiscard]] const std::vector<uint8_t>& get_built_pe() const;
private:
    void rename_sections();
    void update_original_imports(std::vector<uint8_t> &mapped_image, bool restore) const;
    void build_import_descriptor();
    void build_tls();

    [[nodiscard]] uint32_t get_next_section_rva() const;
    void add_section(const std::string &name, const std::vector<uint8_t> &data, uint32_t characteristics);
    void write_rva(uint32_t rva, const void *data, size_t size);
    void set_data_directory(uint32_t index, uint32_t rva, uint32_t size);

    std::shared_ptr<c_pe_image> m_pe_image;
    std::shared_ptr<c_memory_manager> m_memory_manager;

    std::vector<s_themida_recovered_import> m_imports{};

    uint32_t m_address_of_entry_point = 0;

    std::vector<uint8_t> m_built_file{};
    std::vector<uint8_t> m_loader_shellcode{};
    std::vector<uint64_t> m_tls_callbacks{};
    bool m_replace_tls_callbacks = false;
};

#endif //UNTHEMIDATOR_C_PE_BUILDER_HPP
