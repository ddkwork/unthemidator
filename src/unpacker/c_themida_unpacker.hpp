#ifndef UNTHEMIDATOR_C_THEMIDA_UNPACKER_HPP
#define UNTHEMIDATOR_C_THEMIDA_UNPACKER_HPP

#include <deque>
#include <map>

#include "../emulator/c_emulator.hpp"
#include "../pe/c_pe_image.hpp"

#include "themida_structs.hpp"
#include "s_themida_instruction.hpp"
#include "c_loader_generator.hpp"

class c_themida_unpacker {
public:
    c_themida_unpacker(s_unpacker_options options, const std::shared_ptr<c_pe_image>& pe_image,
        const std::shared_ptr<c_emulator_ctx>& emulator_ctx, const std::shared_ptr<c_memory_manager>& memory_manager);

    void decompress_bin();
    void startup();
    void decompress_vms();

    [[nodiscard]] uint32_t get_oep_rva() const;
    [[nodiscard]] const std::vector<uint64_t>& get_tls_callbacks() const { return m_called_addresses; }
    [[nodiscard]] const std::vector<s_themida_recovered_import>& get_recovered_imports() const;
    [[nodiscard]] const std::vector<s_themida_vm_trampoline>& get_vm_trampolines() const { return m_vm_trampolines; }

    [[nodiscard]] const std::vector<uint8_t>& get_loader_shellcode() const;

    [[nodiscard]] std::string get_themida_version() const;

    // helper functions, for internal use
    void on_region_save(uint64_t address, uint32_t size);
    void on_region_made_writable(uint64_t address, uint32_t size);
    void on_original_pe_callback(uint64_t address);
    void on_thread_create(uint64_t address, uint64_t param) const;
private:
    void initialize_runtime_regions();
    [[nodiscard]] static bool preserves_entry_flags(const c_intel_function &function);
    [[nodiscard]] bool is_vm_enter(uint64_t address, std::shared_ptr<c_intel_function> disassembled);
    [[nodiscard]] std::shared_ptr<s_themida_vm_handler> discover_vm_handler(uint64_t address);

    void run_virtual_instruction(uint64_t address);
    void run_decompression_stub(const s_themida_vm_trampoline &trampoline) const;
    bool run_vm_entry_setup(uint64_t address);

    void find_vm_trampolines(uint64_t base_address, const std::vector<uint8_t> &region, bool allow_stealth);
    bool recover_import(uint64_t entry_address);

    std::shared_ptr<c_pe_image> m_pe_image;
    std::shared_ptr<c_emulator_ctx> m_emulator_ctx;
    std::shared_ptr<c_memory_manager> m_memory_manager;
    std::shared_ptr<c_intel_disassembler> m_disassembler;
    std::unique_ptr<c_loader_generator> m_loader;

    std::deque<std::shared_ptr<themida_structs>> m_vm_instances{};
    std::unordered_map<uint64_t, std::shared_ptr<s_themida_vm_handler>> m_vm_handlers{};
    std::unordered_set<uint64_t> m_known_vm_enters{};

    std::vector<s_themida_vm_trampoline> m_vm_trampolines{};

    // ordered startup calls (TLS callbacks on Windows), startup removes the last address and uses it as OEP
    std::vector<uint64_t> m_called_addresses{};

    uint64_t m_real_entry_address = 0;

	s_unpacker_options m_options;

    bool m_is_multi_vm = false;
    bool m_is_v4 = false;

    std::optional<std::pair<uint64_t, uint64_t>> m_loader_region = std::nullopt;

    std::map<uint64_t, uint32_t> m_local_regions{};

    // map of updated pointers: pointer VA -> initial value
    std::unordered_map<uint64_t, uint64_t> m_updated_pointers{};

    std::vector<s_themida_recovered_import> m_recovered_imports{};
};

#endif //UNTHEMIDATOR_C_THEMIDA_UNPACKER_HPP
