#include "c_pe_builder.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <vector>
#include <cstring>

#include "pe_structs.hpp"
#include "c_pe_image.hpp"
#include "../memory/c_memory_manager.hpp"
#include "../emulator/c_emulator_ctx.hpp"

#undef min
#undef max

namespace {
    template<typename T>
    T read_at(const std::vector<uint8_t> &data, const size_t offset) {
        if (offset > data.size() || sizeof(T) > data.size() - offset) {
            throw std::runtime_error("pe builder: invalid read offset");
        }

        T value{};
        memcpy(&value, data.data() + offset, sizeof(T));
        return value;
    }

    template<typename T>
    void write_at(std::vector<uint8_t> &data, const size_t offset, const T &value) {
        if (offset > data.size() || sizeof(T) > data.size() - offset) {
            throw std::runtime_error("pe builder: invalid write offset");
        }

        memcpy(data.data() + offset, &value, sizeof(T));
    }

    uint32_t align_up(const uint64_t value, const uint32_t alignment) {
        if (!alignment || value > std::numeric_limits<uint32_t>::max() - (alignment - 1)) {
            throw std::runtime_error("pe builder: invalid alignment or image size");
        }

        return static_cast<uint32_t>((value + alignment - 1) / alignment * alignment);
    }
}

using namespace unthemidator::pe;

c_pe_builder::c_pe_builder(const std::shared_ptr<c_pe_image> &pe_image,
    const std::shared_ptr<c_memory_manager> &memory_manager)
    : m_pe_image(pe_image), m_memory_manager(memory_manager) {
    //
}

void c_pe_builder::set_entry_rva(const uint32_t offset) {
    m_address_of_entry_point = static_cast<uint32_t>(offset);
}

void c_pe_builder::set_imports(const std::vector<s_themida_recovered_import> &imports) {
    m_imports = imports;
}

void c_pe_builder::set_loader_shellcode(const std::vector<uint8_t> &shellcode) {
    m_loader_shellcode = shellcode;
}

void c_pe_builder::set_tls_callbacks(const std::vector<uint64_t> &callbacks) {
    m_tls_callbacks = callbacks;
    m_replace_tls_callbacks = true;
}

void c_pe_builder::build(const c_emulator_ctx& ctx) {
    auto mapped_image = m_memory_manager->get_mapped_image();
    // Locate the live resource entry using trusted headers, never the potentially
    // damaged DOS/NT/optional headers in Unicorn. Only this 8-byte entry is read.
    const auto &original = m_pe_image->get_mapped_image();
    const auto original_dos = read_at<s_dos_header>(original, 0);
    const auto original_optional = static_cast<size_t>(original_dos.e_lfanew) +
        sizeof(uint32_t) + sizeof(s_coff_header);
    const auto directories_offset = m_pe_image->is_x64() ? offsetof(s_optional_header_64, data_directory) :
        offsetof(s_optional_header_32, data_directory);
    const auto resource_offset = original_optional + directories_offset +
        k_directory_entry_resource * sizeof(s_data_directory);
    (void)read_at<s_data_directory>(original, resource_offset);
    const auto resource = ctx.read<s_data_directory>(m_pe_image->get_image_base() + resource_offset);
    if (!resource) {
        throw std::runtime_error("pe builder: failed to read live resource directory");
    }
    write_at(mapped_image, resource_offset, *resource);
    const auto dos = read_at<s_dos_header>(mapped_image, 0);

    if (dos.e_magic != k_dos_magic) {
        throw std::runtime_error("pe builder: invalid DOS header");
    }

    const auto nt_offset = static_cast<size_t>(dos.e_lfanew);

    if (read_at<uint32_t>(mapped_image, nt_offset) != k_nt_signature) {
        throw std::runtime_error("pe builder: invalid NT headers");
    }

    const auto coff_offset = nt_offset + sizeof(uint32_t);
    const auto coff = read_at<s_coff_header>(mapped_image, coff_offset);
    const auto optional_offset = coff_offset + sizeof(coff);

    if (optional_offset > mapped_image.size() || coff.size_of_optional_header > mapped_image.size() - optional_offset ||
        coff.size_of_optional_header < 0x40) {
        //
        throw std::runtime_error("pe builder: invalid optional header");
    }

    const auto file_alignment = read_at<uint32_t>(mapped_image, optional_offset + 0x24);
    const auto section_table_offset = optional_offset + coff.size_of_optional_header;
    const auto section_table_size = static_cast<uint64_t>(coff.number_of_sections) * sizeof(s_section_header);

    if (section_table_offset > mapped_image.size() || section_table_size > mapped_image.size() - section_table_offset) {
        throw std::runtime_error("pe builder: invalid section table");
    }

    const auto headers_size = align_up(section_table_offset + section_table_size, file_alignment);

    if (headers_size > mapped_image.size()) {
        throw std::runtime_error("pe builder: truncated PE headers");
    }

    update_original_imports(mapped_image, m_imports.empty());

    m_built_file = std::vector<uint8_t>(headers_size, 0);
    memcpy(m_built_file.data(), mapped_image.data(), headers_size);

    switch (read_at<uint16_t>(mapped_image, optional_offset)) {
        case k_optional_magic_pe32: {
            write_at<uint32_t>(m_built_file, optional_offset + offsetof(s_optional_header_32, image_base),
                static_cast<uint32_t>(m_pe_image->get_image_base()));
            // update address of entry point (RVA)
            write_at<uint32_t>(m_built_file, optional_offset + offsetof(s_optional_header_32, address_of_entry_point),
                m_address_of_entry_point);
            break;
        }

        case k_optional_magic_pe32_plus: {
            write_at<uint64_t>(m_built_file, optional_offset + offsetof(s_optional_header_64, image_base), m_pe_image->get_image_base());
            // update address of entry point (RVA)
            write_at<uint32_t>(m_built_file, optional_offset + offsetof(s_optional_header_64, address_of_entry_point),
                m_address_of_entry_point);
            break;
        }

        default:
            throw std::runtime_error("pe builder: unsupported PE architecture");
    }

    auto raw_cursor = headers_size;

    for (uint32_t i = 0; i < coff.number_of_sections; i++) {
        const auto section_offset = section_table_offset + i * sizeof(s_section_header);
        auto section = read_at<s_section_header>(mapped_image, section_offset);

        const auto section_rva = static_cast<uint64_t>(section.virtual_address);
        const auto virtual_size = static_cast<uint64_t>(section.virtual_size);

        if (!virtual_size) {
            section.size_of_raw_data = 0;
            section.pointer_to_raw_data = 0;

            write_at(m_built_file, section_offset, section);
            continue;
        }

        if (section_rva > mapped_image.size() || virtual_size > mapped_image.size() - section_rva) {
            throw std::runtime_error("pe builder: section outside mapped image");
        }

        // calculate actual RAW section size
        auto meaningful_size = static_cast<size_t>(virtual_size);
        while (meaningful_size && mapped_image[section_rva + meaningful_size - 1] == 0) {
            meaningful_size--;
        }

        if (!meaningful_size) {
            section.size_of_raw_data = 0;
            section.pointer_to_raw_data = 0;

            write_at(m_built_file, section_offset, section);
            continue;
        }

        const auto raw_size = align_up(meaningful_size, file_alignment);

        if (raw_cursor > std::numeric_limits<uint32_t>::max() - raw_size) {
            throw std::runtime_error("pe builder: output file too large");
        }

        section.pointer_to_raw_data = raw_cursor;
        section.size_of_raw_data = raw_size;

        m_built_file.resize(static_cast<size_t>(raw_cursor) + raw_size, 0);

        std::memcpy(m_built_file.data() + raw_cursor, mapped_image.data() + section_rva, meaningful_size);
        raw_cursor += raw_size;

        write_at(m_built_file, section_offset, section);
    }

    write_at(m_built_file, optional_offset + 0x3C, headers_size);

    rename_sections();

    build_import_descriptor();
    build_tls();

    set_data_directory(k_directory_entry_basereloc, 0, 0);
    write_at<uint16_t>(m_built_file, coff_offset + offsetof(s_coff_header, characteristics), coff.characteristics | 1);
    const auto dll_flags = read_at<uint16_t>(m_built_file, optional_offset + offsetof(s_optional_header_32, dll_characteristics));
    write_at<uint16_t>(m_built_file, optional_offset + offsetof(s_optional_header_32, dll_characteristics), dll_flags & ~0x60);
}

const std::vector<uint8_t>& c_pe_builder::get_built_pe() const {
    return m_built_file;
}

void c_pe_builder::rename_sections() {
    auto &output = m_built_file;

    constexpr uint32_t k_permission_mask = k_scn_mem_execute | k_scn_mem_read | k_scn_mem_write;

    struct s_section_rename {
        uint32_t m_permissions;
        const char *m_name;
    };

    constexpr s_section_rename k_section_renames[] = {
        {
            .m_permissions = k_scn_mem_execute | k_scn_mem_read,
            .m_name = ".text"
        },
        {
            .m_permissions = k_scn_mem_read,
            .m_name = ".rdata"
        },
        {
            .m_permissions = k_scn_mem_read | k_scn_mem_write,
            .m_name = ".data"
        },
    };

    const auto dos = read_at<s_dos_header>(output, 0);
    const auto coff_offset = static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t);
    const auto coff = read_at<s_coff_header>(output, coff_offset);
    const auto section_table_offset = coff_offset + sizeof(coff) + coff.size_of_optional_header;

    // rename Themida .idata section if import description was rebuilt
    if (!m_imports.empty()) {
        for (uint32_t i = 0; i < coff.number_of_sections; i++) {
            const auto offset = section_table_offset + i * sizeof(s_section_header);
            auto section = read_at<s_section_header>(output, offset);

            if (const auto section_name = std::string(section.name); section_name.find("idata") == std::string::npos) {
                continue;
            }

            const std::string old_idata = ".old";

            memset(section.name, 0, sizeof(section.name));
            memcpy(section.name, old_idata.c_str(), old_idata.length());

            write_at(output, offset, section);
        }
    }

    for (const auto &[permissions, name] : k_section_renames) {
        size_t matching_offset = 0;
        uint32_t matches = 0;

        for (uint32_t i = 0; i < coff.number_of_sections; i++) {
            const auto offset = section_table_offset + i * sizeof(s_section_header);
            const auto section = read_at<s_section_header>(output, offset);

            const auto section_name = std::string(section.name);

            if ((section.characteristics & k_permission_mask) != permissions) {
                continue;
            }

            // skip Themida sections
            if (section_name == ".boot" || section_name == ".themida" || section_name == ".idata") {
                //
                continue;
            }

            matching_offset = offset;
            matches++;
        }

        if (matches != 1) {
            continue;
        }

        auto section = read_at<s_section_header>(output, matching_offset);

        memset(section.name, 0, sizeof(section.name));
        memcpy(section.name, name, std::strlen(name));

        write_at(output, matching_offset, section);
    }
}

void c_pe_builder::update_original_imports(std::vector<uint8_t> &mapped_image, const bool restore) const {
    const auto &original = m_pe_image->get_mapped_image();
    const auto dos = read_at<s_dos_header>(original, 0);
    const auto optional_offset = static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t) + sizeof(s_coff_header);
    const auto is_x64 = m_pe_image->is_x64();
    const auto directories_offset = is_x64 ? offsetof(s_optional_header_64, data_directory) :
        offsetof(s_optional_header_32, data_directory);
    const auto directory = read_at<s_data_directory>(original,
        optional_offset + directories_offset + k_directory_entry_import * sizeof(s_data_directory));

    if (restore) {
        for (const auto index : { k_directory_entry_import, k_directory_entry_iat, k_directory_entry_bound_import }) {
            const auto offset = optional_offset + directories_offset + index * sizeof(s_data_directory);
            write_at(mapped_image, offset, read_at<s_data_directory>(original, offset));
        }
    }

    if (!directory.virtual_address) {
        return;
    }

    const uint32_t ptr_size = is_x64 ? 8 : 4;
    const uint64_t ordinal_flag = is_x64 ? k_ordinal_flag_64 : k_ordinal_flag_32;

    const auto update = [&](const size_t offset, const size_t size) {
        if (offset > mapped_image.size() || size > mapped_image.size() - offset ||
            offset > original.size() || size > original.size() - offset) {
            throw std::runtime_error("pe builder: original import outside mapped image");
        }

        if (restore) {
            memcpy(mapped_image.data() + offset, original.data() + offset, size);
        } else {
            memset(mapped_image.data() + offset, 0, size);
        }
    };

    const auto update_name = [&](const size_t offset, const size_t prefix) {
        if (offset >= original.size() || prefix >= original.size() - offset) {
            throw std::runtime_error("pe builder: invalid original import name");
        }

        const auto name = original.data() + offset + prefix;
        const auto end = static_cast<const uint8_t*>(memchr(name, 0, original.size() - offset - prefix));

        if (!end) {
            throw std::runtime_error("pe builder: unterminated original import name");
        }

        update(offset, prefix + static_cast<size_t>(end - name) + 1);
    };

    for (size_t offset = directory.virtual_address;; offset += sizeof(s_import_descriptor)) {
        const auto descriptor = read_at<s_import_descriptor>(original, offset);

        if (!descriptor.name) {
            update(offset, sizeof(descriptor));
            break;
        }

        update_name(descriptor.name, 0);

        const auto lookup_rva = descriptor.original_first_thunk ? descriptor.original_first_thunk : descriptor.first_thunk;
        if (lookup_rva) {
            for (size_t thunk = lookup_rva;; thunk += ptr_size) {
                const auto value = is_x64 ? read_at<uint64_t>(original, thunk) : read_at<uint32_t>(original, thunk);

                if (restore) {
                    update(thunk, ptr_size);
                    if (descriptor.first_thunk) {
                        update(static_cast<size_t>(descriptor.first_thunk) + thunk - lookup_rva, ptr_size);
                    }
                }

                if (!value) {
                    break;
                }
                if (!(value & ordinal_flag)) {
                    update_name(value, sizeof(uint16_t));
                }
            }
        }

        update(offset, sizeof(descriptor));
    }
}

void c_pe_builder::build_import_descriptor() {
    if (m_imports.empty()) {
        return;
    }

    const auto is_x64 = m_pe_image->is_x64();
    const uint32_t ptr_size = is_x64 ? 8 : 4;
    const uint64_t ordinal_flag = is_x64 ? k_ordinal_flag_64 : k_ordinal_flag_32;
    const auto idata_rva = get_next_section_rva();

    struct s_import_run {
        std::string m_module;
        uint32_t m_first_thunk;
        std::vector<const s_themida_recovered_import*> m_entries;
    };

    struct s_iat_write {
        uint32_t m_rva;
        uint64_t m_value;
    };

    std::vector<const s_themida_recovered_import*> sorted{};
    sorted.reserve(m_imports.size());

    for (const auto &entry : m_imports) {
        if (entry.m_module.empty() || (!entry.m_is_ordinal && entry.m_function.empty()) ||
            (entry.m_is_ordinal && entry.m_ordinal > UINT16_MAX)) {
            //
            throw std::runtime_error("pe builder: invalid recovered import");
        }

        if (entry.m_iat_rva % ptr_size) {
            throw std::runtime_error("pe builder: unaligned IAT slot");
        }

        sorted.push_back(&entry);
    }

    std::ranges::sort(sorted, [](const auto *a, const auto *b) {
        return a->m_iat_rva < b->m_iat_rva;
    });

    for (size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i - 1]->m_iat_rva == sorted[i]->m_iat_rva) {
            throw std::runtime_error("pe builder: duplicate IAT slot");
        }
    }

    const auto iat_rva = sorted.front()->m_iat_rva;
    const auto iat_end = static_cast<uint64_t>(sorted.back()->m_iat_rva) + 2 * ptr_size;

    if (iat_end > m_memory_manager->get_image_size()) {
        throw std::runtime_error("pe builder: IAT outside mapped image");
    }

    std::vector<s_import_run> runs{};
    runs.reserve(sorted.size());

    for (const auto entry : sorted) {
        if (!runs.empty()) {
            auto &run = runs.back();

            if (const auto expected_rva = static_cast<uint64_t>(run.m_entries.back()->m_iat_rva) + ptr_size;
                expected_rva == entry->m_iat_rva && run.m_module == entry->m_module) {
                //
                run.m_entries.push_back(entry);
                continue;
            }
        }

        s_import_run run{};
        run.m_module = entry->m_module;
        run.m_first_thunk = entry->m_iat_rva;
        run.m_entries.push_back(entry);

        runs.push_back(std::move(run));
    }

    const auto directory_size = static_cast<uint32_t>((runs.size() + 1) * sizeof(s_import_descriptor));

    std::vector<uint8_t> idata(directory_size, 0);
    std::vector<s_iat_write> iat_writes;
    iat_writes.reserve(m_imports.size());

    const auto append = [&](const void *data, const size_t size) -> uint32_t {
        const auto offset = idata.size();

        if (offset > UINT32_MAX || size > UINT32_MAX - offset || static_cast<uint64_t>(idata_rva) + offset + size > UINT32_MAX) {
            throw std::runtime_error("pe builder: .idata RVA overflow");
        }

        idata.resize(offset + size);

        if (size) {
            memcpy(idata.data() + offset, data, size);
        }

        return idata_rva + static_cast<uint32_t>(offset);
    };

    const auto align_data = [&](const size_t alignment) {
        if (const auto padding = (alignment - idata.size() % alignment) % alignment) {
            constexpr uint64_t zero = 0;
            append(&zero, padding);
        }
    };

    const auto append_string = [&](const std::string &value) -> uint32_t {
        return append(value.c_str(), value.size() + 1);
    };

    for (size_t i = 0; i < runs.size(); ++i) {
        const auto &[module_name, first_thunk, entries] = runs[i];

        s_import_descriptor descriptor{};
        descriptor.name = append_string(module_name);
        descriptor.first_thunk = first_thunk;

        align_data(ptr_size);

        if (entries.size() > UINT32_MAX / ptr_size - 1) {
            throw std::runtime_error("pe builder: import lookup table too large");
        }

        const auto ilt_size = (entries.size() + 1) * ptr_size;
        const std::vector<uint8_t> empty_ilt(ilt_size, 0);

        descriptor.original_first_thunk = append(empty_ilt.data(), empty_ilt.size());

        for (size_t j = 0; j < entries.size(); ++j) {
            const auto &entry = *entries[j];

            uint64_t thunk_value = 0;

            if (entry.m_is_ordinal) {
                thunk_value = ordinal_flag | entry.m_ordinal;
            } else {
                align_data(2);

                constexpr uint16_t hint = 0;
                const auto name_rva = append(&hint, sizeof(hint));

                append_string(entry.m_function);
                thunk_value = name_rva;
            }

            const auto ilt_offset = static_cast<size_t>(descriptor.original_first_thunk - idata_rva) +
                j * ptr_size;

            memcpy(idata.data() + ilt_offset, &thunk_value, ptr_size);

            iat_writes.push_back({
                .m_rva = entry.m_iat_rva,
                .m_value = thunk_value
            });
        }

        memcpy(idata.data() + i * sizeof(s_import_descriptor), &descriptor, sizeof(descriptor));
    }

    add_section(".idata", idata, k_scn_cnt_initialized_data | k_scn_mem_read);

    for (const auto &[rva, value] : iat_writes) {
        write_rva(rva, &value, ptr_size);
    }

    set_data_directory(k_directory_entry_import, idata_rva, directory_size);
    set_data_directory(k_directory_entry_iat, iat_rva, static_cast<uint32_t>(iat_end - iat_rva));
    set_data_directory(k_directory_entry_bound_import, 0, 0);
}

void c_pe_builder::build_tls() {
    if (m_loader_shellcode.empty() && !m_replace_tls_callbacks) {
        return;
    }

    const auto is_x64 = m_pe_image->is_x64();
    const uint32_t ptr_size = is_x64 ? 8 : 4;
    const uint32_t directory_size = 4 * ptr_size + 8;

    const auto image_base = m_pe_image->get_image_base();
    const auto &mapped = m_memory_manager->get_mapped_image();

    const auto dos = read_at<s_dos_header>(mapped, 0);
    const auto optional_offset = static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t) + sizeof(s_coff_header);
    const auto directories_offset = is_x64 ? offsetof(s_optional_header_64, data_directory) :
        offsetof(s_optional_header_32, data_directory);

    const auto [virtual_address, size] = read_at<s_data_directory>(mapped,
        optional_offset + directories_offset + k_directory_entry_tls * sizeof(s_data_directory));

    std::vector<uint8_t> tls(directory_size, 0);
    std::vector<uint64_t> callbacks{};

    const auto read_pointer = [&](const auto &data, const size_t offset) -> uint64_t {
        return is_x64 ? read_at<uint64_t>(data, offset) : read_at<uint32_t>(data, offset);
    };

    const auto write_pointer = [&](const size_t offset, const uint64_t value) {
        if (!is_x64 && value > UINT32_MAX) {
            throw std::runtime_error("pe builder: TLS address exceeds 32 bits");
        }

        memcpy(tls.data() + offset, &value, ptr_size);
    };

    if (virtual_address) {
        if (size < directory_size || virtual_address > mapped.size() ||
            directory_size > mapped.size() - virtual_address) {
            //
            throw std::runtime_error("pe builder: invalid existing TLS directory");
        }

        memcpy(tls.data(), mapped.data() + virtual_address, directory_size);

        if (auto callback_array = read_pointer(tls, 3 * ptr_size); callback_array && !m_replace_tls_callbacks) {
            for (;;) {
                if (callback_array < image_base || callback_array - image_base > mapped.size() ||
                    ptr_size > mapped.size() - (callback_array - image_base)) {
                    //
                    throw std::runtime_error("pe builder: invalid TLS callback array");
                }

                const auto callback = read_pointer(mapped, callback_array - image_base);

                if (!callback) {
                    break;
                }

                callbacks.push_back(callback);
                callback_array += ptr_size;
            }
        }
    }

    if (m_replace_tls_callbacks) {
        callbacks = m_tls_callbacks;
    }

    if (!m_loader_shellcode.empty()) {
        const auto loader_rva = get_next_section_rva();
        add_section(".fixer", m_loader_shellcode, k_scn_cnt_code | k_scn_mem_read | k_scn_mem_execute);
        callbacks.insert(callbacks.begin(), image_base + loader_rva);
    }

    const auto tls_rva = get_next_section_rva();
    const auto index_offset = directory_size;
    const auto callbacks_offset = align_up(index_offset + sizeof(uint32_t), ptr_size);
    const auto tls_size = static_cast<uint64_t>(callbacks_offset) + (callbacks.size() + 1ULL) * ptr_size;

    if (tls_size > UINT32_MAX || image_base > UINT64_MAX - tls_rva - tls_size ||
        (!is_x64 && image_base + tls_rva + tls_size > UINT32_MAX)) {
        //
        throw std::runtime_error("pe builder: TLS address overflow");
    }

    tls.resize(tls_size, 0);
    const auto index_address = image_base + tls_rva + index_offset;

    if (!virtual_address) {
        write_pointer(0, index_address);
        write_pointer(ptr_size, index_address);
    }
    if (!read_pointer(tls, 2 * ptr_size)) {
        write_pointer(2 * ptr_size, index_address);
    }

    write_pointer(3 * ptr_size, image_base + tls_rva + callbacks_offset);
    for (size_t i = 0; i < callbacks.size(); ++i) {
        write_pointer(callbacks_offset + i * ptr_size, callbacks[i]);
    }

    add_section(".tls", tls, k_scn_cnt_initialized_data | k_scn_mem_read | k_scn_mem_write);
    set_data_directory(k_directory_entry_tls, tls_rva, directory_size);
}

uint32_t c_pe_builder::get_next_section_rva() const {
    const auto dos = read_at<s_dos_header>(m_built_file, 0);
    const auto coff_offset = static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t);
    const auto coff = read_at<s_coff_header>(m_built_file, coff_offset);
    const auto optional_offset = coff_offset + sizeof(coff);

    const auto section_alignment = read_at<uint32_t>(m_built_file, optional_offset + 0x20);
    const auto size_of_image = read_at<uint32_t>(m_built_file, optional_offset + 0x38);
    const auto sections_offset = optional_offset + coff.size_of_optional_header;

    if (!section_alignment) {
        throw std::runtime_error("pe builder: invalid section alignment");
    }

    uint64_t next_rva = size_of_image;

    for (uint32_t i = 0; i < coff.number_of_sections; ++i) {
        const auto section = read_at<s_section_header>(m_built_file, sections_offset + i * sizeof(s_section_header));

        const auto section_end = static_cast<uint64_t>(section.virtual_address) +
            std::max(section.virtual_size, section.size_of_raw_data);

        next_rva = std::max(next_rva, section_end);
    }

    return align_up(next_rva, section_alignment);
}

void c_pe_builder::add_section(const std::string &name, const std::vector<uint8_t> &data, const uint32_t characteristics) {
    if (name.empty() || name.size() > 8) {
        throw std::runtime_error("pe builder: invalid section name");
    }

    if (data.empty() || data.size() > UINT32_MAX) {
        throw std::runtime_error("pe builder: invalid section data");
    }

    const auto dos = read_at<s_dos_header>(m_built_file, 0);

    if (dos.e_magic != k_dos_magic) {
        throw std::runtime_error("pe builder: invalid DOS header");
    }

    const auto nt_offset = static_cast<size_t>(dos.e_lfanew);

    if (read_at<uint32_t>(m_built_file, nt_offset) != k_nt_signature) {
        throw std::runtime_error("pe builder: invalid NT headers");
    }

    const auto coff_offset = nt_offset + sizeof(uint32_t);
    auto coff = read_at<s_coff_header>(m_built_file, coff_offset);
    const auto optional_offset = coff_offset + sizeof(coff);
    const auto sections_offset = optional_offset + coff.size_of_optional_header;

    if (coff.number_of_sections == UINT16_MAX) {
        throw std::runtime_error("pe builder: too many sections");
    }

    const auto section_alignment = read_at<uint32_t>(m_built_file, optional_offset + 0x20);
    const auto file_alignment = read_at<uint32_t>(m_built_file, optional_offset + 0x24);
    const auto headers_size = read_at<uint32_t>(m_built_file, optional_offset + 0x3C);

    if (!section_alignment || !file_alignment || headers_size > m_built_file.size()) {
        throw std::runtime_error("pe builder: invalid PE alignment or headers");
    }

    const auto section_rva = get_next_section_rva();
    const auto raw_size = align_up(data.size(), file_alignment);

    const uint64_t section_end = static_cast<uint64_t>(section_rva) + data.size();

    if (section_end > UINT32_MAX) {
        throw std::runtime_error("pe builder: section RVA overflow");
    }

    const auto new_size_of_image = align_up(section_end, section_alignment);

    const uint64_t header_offset = static_cast<uint64_t>(sections_offset) + static_cast<uint64_t>(coff.number_of_sections) *
        sizeof(s_section_header);
    const uint64_t required_header_end = header_offset + sizeof(s_section_header);

    if (header_offset > UINT32_MAX || required_header_end > UINT32_MAX) {
        throw std::runtime_error("pe builder: section header overflow");
    }

    const auto new_headers_size = align_up(std::max<uint64_t>(required_header_end, headers_size),
        file_alignment);

    if (new_headers_size > headers_size) {
        const auto shift = new_headers_size - headers_size;

        // Existing section data must not overlap the header insertion point.
        for (uint32_t i = 0; i < coff.number_of_sections; ++i) {
            const auto offset = sections_offset + i * sizeof(s_section_header);
            const auto section = read_at<s_section_header>(m_built_file, offset);

            if (!section.size_of_raw_data) {
                continue;
            }

            if (section.pointer_to_raw_data < headers_size || static_cast<uint64_t>(section.pointer_to_raw_data) +
                section.size_of_raw_data > m_built_file.size()) {
                //
                throw std::runtime_error("pe builder: invalid existing section layout");
            }

            if (section.pointer_to_raw_data > UINT32_MAX - shift) {
                throw std::runtime_error("pe builder: raw section offset overflow");
            }
        }

        m_built_file.insert(m_built_file.begin() + headers_size, shift, 0);

        for (uint32_t i = 0; i < coff.number_of_sections; ++i) {
            const auto offset = sections_offset + i * sizeof(s_section_header);
            auto section = read_at<s_section_header>(m_built_file, offset);

            if (!section.size_of_raw_data) {
                continue;
            }

            section.pointer_to_raw_data += shift;
            write_at(m_built_file, offset, section);
        }
    }

    const auto raw_offset = align_up(m_built_file.size(), file_alignment);

    if (static_cast<uint64_t>(raw_offset) + raw_size > UINT32_MAX) {
        throw std::runtime_error("pe builder: output file too large");
    }

    s_section_header section{};

    memcpy(section.name, name.data(), name.size());

    section.virtual_address = section_rva;
    section.virtual_size = static_cast<uint32_t>(data.size());
    section.pointer_to_raw_data = raw_offset;
    section.size_of_raw_data = raw_size;
    section.characteristics = characteristics;

    m_built_file.resize(static_cast<size_t>(raw_offset) + raw_size, 0);
    memcpy(m_built_file.data() + raw_offset, data.data(), data.size());

    write_at(m_built_file, header_offset, section);

    coff.number_of_sections++;
    write_at(m_built_file, coff_offset, coff);

    write_at(m_built_file, optional_offset + 0x38, new_size_of_image);
    write_at(m_built_file, optional_offset + 0x3C, new_headers_size);

    if (characteristics & (k_scn_cnt_code | k_scn_cnt_initialized_data)) {
        const auto size_offset = optional_offset + ((characteristics & k_scn_cnt_code) ? 0x04 : 0x08);
        const auto initialized_size = read_at<uint32_t>(m_built_file, size_offset);

        if (initialized_size > UINT32_MAX - raw_size) {
            throw std::runtime_error("pe builder: initialized data size overflow");
        }

        write_at(m_built_file, size_offset, initialized_size + raw_size);
    }
}

void c_pe_builder::write_rva(const uint32_t rva, const void *data, const size_t size) {
    if (!size) {
        return;
    }

    if (!data) {
        throw std::runtime_error("pe builder: null write buffer");
    }

    const auto dos = read_at<s_dos_header>(m_built_file, 0);
    const auto coff_offset = static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t);
    const auto coff = read_at<s_coff_header>(m_built_file, coff_offset);
    const auto sections_offset = coff_offset + sizeof(coff) + coff.size_of_optional_header;

    for (uint32_t i = 0; i < coff.number_of_sections; ++i) {
        const auto section = read_at<s_section_header>(m_built_file, sections_offset + i * sizeof(s_section_header));

        if (rva < section.virtual_address) {
            continue;
        }

        const uint64_t offset = static_cast<uint64_t>(rva) - section.virtual_address;

        if (offset >= section.size_of_raw_data || size > section.size_of_raw_data - offset) {
            continue;
        }

        const uint64_t file_offset = static_cast<uint64_t>(section.pointer_to_raw_data) + offset;

        if (file_offset > m_built_file.size() || size > m_built_file.size() - file_offset) {
            throw std::runtime_error("pe builder: invalid section raw data");
        }

        memcpy(m_built_file.data() + file_offset, data, size);
        return;
    }

    throw std::runtime_error("pe builder: RVA has no writable raw-file backing");
}

void c_pe_builder::set_data_directory(const uint32_t index, const uint32_t rva, const uint32_t size) {
    //
    const auto dos = read_at<s_dos_header>(m_built_file, 0);
    const auto coff_offset = static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t);
    const auto coff = read_at<s_coff_header>(m_built_file, coff_offset);
    const auto optional_offset = coff_offset + sizeof(coff);

    const auto magic = read_at<uint16_t>(m_built_file, optional_offset);

    size_t directory_offset = 0;
    size_t count_offset = 0;

    switch (magic) {
        case k_optional_magic_pe32: {
            directory_offset = offsetof(s_optional_header_32, data_directory);
            count_offset = directory_offset - sizeof(uint32_t);
            break;
        }

        case k_optional_magic_pe32_plus: {
            directory_offset = offsetof(s_optional_header_64, data_directory);
            count_offset = directory_offset - sizeof(uint32_t);
            break;
        }

        default:
            throw std::runtime_error("pe builder: unsupported optional header");
    }

    if (coff.size_of_optional_header < directory_offset || count_offset + sizeof(uint32_t) > coff.size_of_optional_header) {
        throw std::runtime_error("pe builder: truncated optional header");
    }

    const auto number_of_directories = read_at<uint32_t>(
        m_built_file, optional_offset + count_offset);

    if (index >= number_of_directories || directory_offset + (static_cast<uint64_t>(index) + 1) *
        sizeof(s_data_directory) > coff.size_of_optional_header) {
        //
        throw std::runtime_error("pe builder: data directory index out of range");
    }

    s_data_directory directory{};
    directory.virtual_address = rva;
    directory.size = size;

    const auto offset = optional_offset + directory_offset + index * sizeof(s_data_directory);
    write_at(m_built_file, offset, directory);
}
