#ifndef UNTHEMIDATOR_C_IMPORTS_HPP
#define UNTHEMIDATOR_C_IMPORTS_HPP

#include <unordered_map>

struct s_dummy_export;
class c_emulator_ctx;

class c_imports {
public:
    explicit c_imports(c_emulator_ctx *emulator_ctx);

    uint64_t load_module(std::string module_name);

    [[nodiscard]] uint64_t resolve_import(const std::string &module_name, const std::string &function_name) const;
    [[nodiscard]] uint64_t resolve_import(uint64_t module_base, const std::string &function_name) const;
    [[nodiscard]] uint64_t resolve_import(uint64_t module_base, uint16_t ordinal) const;

    const s_dummy_export * find_import_by_address(uint64_t address);
private:
    c_emulator_ctx *m_emulator_ctx;

    std::unordered_map<std::string, uint64_t> m_module_addresses{};
    std::unordered_map<uint64_t, std::string> m_modules{};

    std::unordered_map<std::string, std::unordered_map<std::string, s_dummy_export>> m_exports_by_name{};
    std::unordered_map<uint64_t, std::pair<std::string, std::string>> m_exports_by_va{};
};

#endif //UNTHEMIDATOR_C_IMPORTS_HPP
