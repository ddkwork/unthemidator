#include "c_themida_unpacker.hpp"

#include <algorithm>
#include <iostream>
#include <chrono>
#include <fstream>
#include <ranges>

#include "../emulator/hooks.hpp"
#include "../pe/pe_structs.hpp"

#undef max

c_themida_unpacker::c_themida_unpacker(const s_unpacker_options options, const std::shared_ptr<c_pe_image> &pe_image,
    const std::shared_ptr<c_emulator_ctx> &emulator_ctx, const std::shared_ptr<c_memory_manager> &memory_manager)
    : m_pe_image(pe_image), m_emulator_ctx(emulator_ctx), m_memory_manager(memory_manager), m_options(options) {
    //
    m_emulator_ctx->set_themida_unpacker(this);
    m_disassembler = std::make_shared<c_intel_disassembler>(m_memory_manager, pe_image->is_x64());

    if (!m_options.m_skip_loader) {
        m_loader = std::make_unique<c_loader_generator>();
    }
}

void c_themida_unpacker::decompress_bin() {
    const auto start = std::chrono::high_resolution_clock::now();

    m_real_entry_address = m_pe_image->get_entry_rva() + m_memory_manager->get_image_base();

    // check if the entry point is packed: there should be a call to function
    // that has a pop (of ret addr) as its first instruction
    if (m_emulator_ctx->read<uint8_t>(m_real_entry_address) != 0xE8) {
        std::cout << "[unthemidator][decompressor] binary is not compressed" << std::endl;
        return;
    }

    const auto va = static_cast<uint64_t>(m_emulator_ctx->read<int32_t>(m_real_entry_address + 1).value() +
        static_cast<int64_t>(m_real_entry_address + 5));

    if (va < m_memory_manager->get_image_base() || va >= m_memory_manager->get_image_base() + m_memory_manager->get_image_size()) {
        //
        throw std::runtime_error("decompress bin: invalid jump target!");
    }

    // disassemble function
    const auto fn = m_disassembler->disassemble(static_cast<uint32_t>(va - m_memory_manager->get_image_base()));

    if (!fn || fn->m_basic_blocks.size() < 2) {
        std::cout << "[unthemidator][decompressor] binary is not compressed (1)" << std::endl;
        return;
    }

    // check first instruction of target function is POP
    if (fn->m_basic_blocks.at(fn->m_first_bb_id).m_instructions.begin()->m_instruction.mnemonic != ZYDIS_MNEMONIC_POP) {
        std::cout << "[unthemidator][decompressor] binary is not compressed (2)" << std::endl;
        return;
    }

    // last instruction of target function should be jump
    if (fn->m_final_block_ids.size() != 1) {
        throw std::runtime_error("decompress bin: unexpected decompression function");
    }

    const auto &last_insn = *fn->m_basic_blocks.at(*fn->m_final_block_ids.begin()).m_instructions.rbegin();

    if (last_insn.m_instruction.mnemonic != ZYDIS_MNEMONIC_JMP) {
        throw std::runtime_error("decompress bin: unexpected decompression function epilogue");
    }

    std::cout << "[unthemidator][decompressor] unpacking..." << std::endl;

    const auto image_base = m_memory_manager->get_image_base();
    const auto image_end = image_base + m_memory_manager->get_image_size();

    m_loader_region = std::make_pair(image_end, image_base);

    // run decompression loop until the jmp to real EP
    m_emulator_ctx->run(m_real_entry_address, m_memory_manager->get_image_base() + last_insn.m_rva, nullptr,
        [&, image_base, image_end](uc_engine*, const uc_mem_type type, const uint64_t address, int, int64_t) -> void {
            if (type != UC_MEM_WRITE || address < image_base || address >= image_end) {
                return;
            }

            if (address < m_loader_region->first) {
                m_loader_region->first = address;
            }

            if (address > m_loader_region->second) {
                m_loader_region->second = address;
            }
        });

    // step onto the next PC
    m_emulator_ctx->single_step();

    // update real entry point address
    m_real_entry_address = m_emulator_ctx->get_pc();

    // synchronize emulated image with image in memory
    std::vector<uint8_t> decompressed_dump{};
    decompressed_dump.resize(m_memory_manager->get_image_size());

    const auto last_err = uc_mem_read(m_emulator_ctx->get_uc(), m_memory_manager->get_image_base(), decompressed_dump.data(),
                                      decompressed_dump.size());

    if (last_err != UC_ERR_OK) {
        throw std::runtime_error("decompress bin: failed to read emulator memory: " + std::to_string(last_err));
    }

    m_memory_manager->write_memory(m_memory_manager->get_image_base(), decompressed_dump);

    const auto end = std::chrono::high_resolution_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "[unthemidator][decompressor] unpacking finished in " << duration << " ms" << std::endl;
    std::cout << "[unthemidator][decompressor] OEP address - 0x" << std::hex << m_real_entry_address << std::dec << std::endl;
}

void c_themida_unpacker::startup() {
    const auto start = std::chrono::high_resolution_clock::now();

    std::cout << "[unthemidator][startup] starting Themida runtime..." << std::endl;

    // discover VM enter as a handler
    const auto vm_enter = discover_vm_handler(m_real_entry_address);

    if (!vm_enter || !vm_enter->m_disassembled || vm_enter->m_type != e_themida_handler_type::context_switch) {
        std::cout << "[unthemidator] no themida runtime was found" << std::endl;
        return;
    }

    m_vm_handlers.emplace(m_real_entry_address, vm_enter);

    // initialize entrypoint call arguments (assume default dll entry signature)
    m_emulator_ctx->set_arg(0, m_memory_manager->get_image_base());
    m_emulator_ctx->set_arg(1, 1); // DLL_PROCESS_ATTACH
    m_emulator_ctx->set_arg(2, 0);

    // try running vm enter
    if (!run_vm_entry_setup(m_real_entry_address)) {
        std::cout << "[unthemidator] no themida runtime was found" << std::endl;
        return;
    }

    std::cout << "[unthemidator][startup] multiple vCPUs (asynchronous execution) support: " <<
        (m_is_multi_vm ? "YES" : "NO") << std::endl;

    const auto image_base = m_memory_manager->get_image_base();
    const auto image_end = image_base + m_memory_manager->get_image_size();

    auto pc = m_emulator_ctx->get_pc();

    // add image-wide memory callback to log NX pages execution attempt to catch non-virtualized OEP
    m_emulator_ctx->add_mem_hook(UC_HOOK_MEM_FETCH_PROT,
        [&](uc_engine*, const uc_mem_type, const uint64_t addr, const int, const int64_t) -> void {
            m_found_oep = true;
            m_real_entry_address = addr;

            on_first_vm_enter(addr);
            m_emulator_ctx->remove_mem_hook(image_base);

        }, image_base, image_end);

    if (m_options.m_max_nested_vms > 0) {
        while (true) {
            pc = m_emulator_ctx->get_pc();

            // if current RIP is not within the image, single step until a hook as fired or any other kind of magic happens
            if (pc < image_base || pc >= image_end) {
                m_emulator_ctx->single_step();

                if (m_found_oep) {
                    break;
                }

                continue;
            }

            run_virtual_instruction(pc);

            // nothing left to run if OEP has been found already
            if (m_found_oep || m_emulator_ctx->get_pc() == 0) {
                break;
            }
        }
    } else {
        m_emulator_ctx->run(pc, 0);
    }

    m_emulator_ctx->remove_mem_hook(image_base);

    // recover imports (IAT) pointers
    if (!m_options.m_skip_imports) {
        for (const auto addr: m_updated_pointers | std::views::keys) {
            if (addr <= image_base + m_pe_image->get_size_of_headers()) {
                continue;
            }

            if (recover_import(addr)) {
                continue;
            }
        }
    }

    std::ranges::sort(m_recovered_imports, {}, &s_themida_recovered_import::m_iat_rva);

    std::cout << "[unthemidator][startup] successfully recovered " << m_recovered_imports.size() << " imports" << std::endl;

    const auto end = std::chrono::high_resolution_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "[unthemidator][startup] Themida runtime finished in " << duration << " ms" << std::endl;
}

void c_themida_unpacker::decompress_vms() {
    const auto start = std::chrono::high_resolution_clock::now();

    std::cout << "[unthemidator][vm decompressor] decompressing virtual machines..." << std::endl;

    // if no VM trampolines were found prior to decompress VMs call,
    // iterate over known executable sections and find trampolines including stealth one
    if (m_vm_trampolines.empty()) {
        const auto &mapped_image = m_memory_manager->get_mapped_image();
        uint16_t section_idx = 0;

        for (const auto &section: m_pe_image->get_sections()) {
            section_idx++;

            if (!(section.characteristics & unthemidator::pe::k_scn_mem_execute)) {
                continue;
            }

            std::vector section_dump(mapped_image.begin() + section.virtual_address,
                mapped_image.begin() + section.virtual_address + section.virtual_size);

            find_vm_trampolines(m_memory_manager->get_image_base() + section.virtual_address,
                section_dump, (section_idx == 1));
        }
    }

    std::unordered_set<uint64_t> vm_enters{};

    // iterate over all trampolines and decompress unique vm enters
    for (const auto &vm_trampoline: m_vm_trampolines) {
        if (!vm_trampoline.m_is_packed) {
            continue;
        }

        if (!vm_enters.insert(vm_trampoline.m_vm_enter_address).second) {
            continue;
        }

        run_decompression_stub(vm_trampoline);
    }

    const auto end = std::chrono::high_resolution_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "[unthemidator][vm decompressor] decompressed " << vm_enters.size() << " VMs in " << duration << " ms" << std::endl;
}

uint32_t c_themida_unpacker::get_oep_rva() const {
    return static_cast<uint32_t>(m_real_entry_address - m_memory_manager->get_image_base());
}

const std::vector<s_themida_recovered_import> &c_themida_unpacker::get_recovered_imports() const {
    return m_recovered_imports;
}

void c_themida_unpacker::on_region_save(const uint64_t address, const uint32_t size) {
    on_region_made_writable(address, size);

    // save final version of region
    std::vector<uint8_t> region_dump(size, 0);
    uc_mem_read(m_emulator_ctx->get_uc(), address, region_dump.data(), region_dump.size());

    m_memory_manager->write_memory(address, region_dump);

    // if region is executable, find all potential jumps to VM
    if (m_pe_image->is_rva_in_executable_section(address - m_memory_manager->get_image_base())) {
        if (m_vm_trampolines.empty()) {
            find_vm_trampolines(address, region_dump, false);
        }

        // hook all vm enters to catch OEP addr
        for (auto &trampoline : m_vm_trampolines) {
            std::vector<uint8_t> bp_prologue(4, 0xCC);
            trampoline.m_prologue = std::vector<uint8_t>(4, 0);

            // save original bytes
            uc_mem_read(m_emulator_ctx->get_uc(), trampoline.m_vm_enter_address, trampoline.m_prologue.data(),
                        trampoline.m_prologue.size());

            // patch first 4 bytes making them sequence of INT3s to trigger the hook
            uc_mem_write(m_emulator_ctx->get_uc(), trampoline.m_vm_enter_address, bp_prologue.data(), bp_prologue.size());

            m_emulator_ctx->add_hook(trampoline.m_vm_enter_address, "potential_entry", hooks::vm_enter);
        }

        // apply NX protection so when emulator reaches OEP, it'd immediately throw
        uc_mem_protect(m_emulator_ctx->get_uc(), address, page_up(size, 0x1000),
            UC_PROT_READ | UC_PROT_WRITE);
    }

    std::cout << "[unthemidator][runtime] saved unpacked region (section): 0x" << std::hex << address <<
        " -> 0x" << (address + size) << std::dec << std::endl;
}

void c_themida_unpacker::on_region_made_writable(const uint64_t address, const uint32_t size) {
    const auto image_base = m_memory_manager->get_image_base();
    const auto image_size = m_memory_manager->get_image_size();

    if (address < image_base || address - image_base >= image_size || !size || size > image_size - (address - image_base)) {
        return;
    }

    m_local_regions[address] = std::max(m_local_regions[address], size);

    m_emulator_ctx->remove_mem_hook(address);

    const auto ptr_size = m_pe_image->get_ptr_size();
    const auto region_size = m_local_regions.at(address);

    m_emulator_ctx->add_mem_hook(UC_HOOK_MEM_WRITE, [this, address, region_size, ptr_size](uc_engine* uc, const uc_mem_type,
        const uint64_t addr, const int sz, const int64_t value) {
        //
        if (sz != ptr_size || addr < address || addr - address >= region_size || ptr_size > region_size - (addr - address)) {
            return;
        }

        if (m_updated_pointers.contains(addr)) {
            return;
        }

        uint64_t orig_value = 0;
        uc_mem_read(uc, addr, &orig_value, ptr_size);

        if (orig_value) {
            m_updated_pointers.emplace(addr, orig_value);
        } else {
            m_updated_pointers.emplace(addr,
                ptr_size == 4 ? static_cast<uint32_t>(value) : static_cast<uint64_t>(value));
        }
    }, address, address + region_size - 1);
}

void c_themida_unpacker::on_first_vm_enter(const uint64_t address) {
    // fixme: this assumes that the first call to the .text section is OEP,
    //  which is not always the case, for example TLS callbacks go first
    m_emulator_ctx->stop(address);

    // restore vm enters' prologues
    for (const auto &trampoline : m_vm_trampolines) {
        // restore prologue
        uc_mem_write(m_emulator_ctx->get_uc(), trampoline.m_vm_enter_address, trampoline.m_prologue.data(),
            trampoline.m_prologue.size());

        // remove hook
        m_emulator_ctx->remove_hook(trampoline.m_vm_enter_address);
    }

    for (const auto &trampoline : m_vm_trampolines) {
        if (trampoline.m_vm_enter_address == address) {
            m_real_entry_address = trampoline.m_trampoline_address;

            m_found_oep = true;
            break;
        }
    }

    if (!m_found_oep) {
        throw std::runtime_error("failed to find OEP");
    }

    std::cout << "[unthemidator][runtime] OEP found - 0x" << std::hex << m_real_entry_address << std::dec << std::endl;

    // bypass loader anti-dump by manually fixing some pointers
    if (m_loader_region.has_value()) {
        std::vector<uint8_t> loader(m_loader_region->second - m_loader_region->first, 0);
        uc_mem_read(m_emulator_ctx->get_uc(), m_loader_region->first, loader.data(), loader.size());

        const auto &mapped = m_memory_manager->get_mapped_image();
        const auto og_loader = mapped.data() + m_loader_region->first - m_memory_manager->get_image_base();

        const auto ptr_size = m_pe_image->get_ptr_size();

        const auto committed_base = m_memory_manager->get_committed_memory_start();
        const auto committed_end = m_memory_manager->get_memory_end();

        // compare loader binary at the moment of OEP invocation (now) and its initial version,
        // find all addresses (of funcs, module bases etc) as well as magic values to patch them
        // this is done to fix Themida's anti-dump and make a runnable binary
        for (size_t i = 0 ; i < loader.size() - ptr_size + 1; i++) {
            const auto ptr_val = ptr_size == 8 ? *reinterpret_cast<const uint64_t*>(loader.data() + i) :
                static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(loader.data() + i));
            const auto og_ptr_val = ptr_size == 8 ? *reinterpret_cast<const uint64_t*>(og_loader + i) :
                static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(og_loader + i));

            if (ptr_val == og_ptr_val) {
                continue;
            }

            if (ptr_val < committed_base || ptr_val >= committed_end) {
                continue;
            }

            if (!m_memory_manager->get_address_tag(ptr_val).has_value()) {
                continue;
            }

            //*reinterpret_cast<uint64_t*>(loader.data() + i) = 0; // todo
            i += m_pe_image->get_ptr_size() - 1;
        }

        // update loader region with its last version
        m_memory_manager->write_memory(m_loader_region->first, loader);
    }

    // update all local regions with their final values
    for (const auto &[region_address, region_size] : m_local_regions) {
        m_emulator_ctx->remove_mem_hook(region_address);

        std::vector<uint8_t> region_dump(region_size, 0);

        if (uc_mem_read(m_emulator_ctx->get_uc(), region_address, region_dump.data(), region_dump.size()) != UC_ERR_OK) {
            throw std::runtime_error("failed to read local region");
        }

        m_memory_manager->write_memory(region_address, region_dump);
    }

    // generate runtime fixer shellcode (TLS callback)
    if (m_loader) {
        m_loader->generate(m_emulator_ctx->get_arch());
    }
}

void c_themida_unpacker::on_thread_create(const uint64_t address, const uint64_t param) const {
    const auto sleep_fn = m_emulator_ctx->get_imports()->resolve_import("kernel32.dll",
        "Sleep");

    std::cout << "[unthemidator][startup] emulating observer thread 0x" <<
        std::hex << address << ", param: 0x" << param << std::dec << "..." << std::endl;

    // emulate asynchronous routine until Sleep function call,
    // cause when we're in the loop, it's safe to continue with unpacking
    m_emulator_ctx->run_thread(address, sleep_fn, param);
}

const std::vector<uint8_t>& c_themida_unpacker::get_loader_shellcode() const {
    if (!m_loader) {
        static const std::vector<uint8_t> empty{};
        return empty;
    }

    return m_loader->get_shellcode();
}

std::string c_themida_unpacker::get_themida_version() const {
    if (m_is_v4) {
        return "v4";
    }

    if (m_is_multi_vm) {
        // Themida [3.2.0.0] (28-Aug-2024): Added parallel execution within each VM instance
        // (32 virtual cores by default), from https://www.oreans.com/ThemidaAllWhatsNew.php

        return "v3.2.0.0 - v3.2.6.0";
    }

    return "v3.0 - v3.1.9.0";
}

bool c_themida_unpacker::should_stop([[maybe_unused]] const uint64_t address) const {
    return m_found_oep;
}

bool c_themida_unpacker::preserves_entry_flags(const c_intel_function &function) {
    std::unordered_set<size_t> checked_bbs{};
    std::unordered_set<ZydisRegister> modified_regs{};

    auto bb_id = function.m_first_bb_id;

    while (checked_bbs.insert(bb_id).second) {
        const auto &bb = function.m_basic_blocks.at(bb_id);

        for (const auto &instr : bb.m_instructions) {
            const auto mnemonic = instr.m_instruction.mnemonic;
            const auto &destination = instr.m_operands[0];

            const bool adjusts_saved_register =
                (mnemonic == ZYDIS_MNEMONIC_SUB || mnemonic == ZYDIS_MNEMONIC_ADD) &&
                destination.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                modified_regs.contains(destination.reg.value);

            if (const auto flags = instr.m_instruction.cpu_flags) {
                if ((flags->modified | flags->set_0 | flags->set_1 | flags->undefined) != 0 &&
                    !adjusts_saved_register) {
                    //
                    return false;
                }
            }

            if ((mnemonic == ZYDIS_MNEMONIC_POP || mnemonic == ZYDIS_MNEMONIC_PUSH) &&
                destination.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                //
                modified_regs.insert(destination.reg.value);
            }

            if (instr.m_instruction.mnemonic == ZYDIS_MNEMONIC_PUSHFQ ||
                instr.m_instruction.mnemonic == ZYDIS_MNEMONIC_PUSHFD) {
                return true;
            }
        }

        if (bb.m_is_final || bb.m_successors.size() != 1) {
            return false;
        }

        bb_id = bb.m_successors.back();
    }

    return false;
}

bool c_themida_unpacker::is_vm_enter(const uint64_t address, std::shared_ptr<c_intel_function> disassembled) {
    const auto image_base = m_memory_manager->get_image_base();
    const auto rva = static_cast<uint32_t>(address - image_base);

    if (address < image_base || address >= image_base + m_memory_manager->get_image_size()) {
        return false;
    }

    if (m_known_vm_enters.contains(address)) {
        return true;
    }

    if (!disassembled) {
        disassembled = m_disassembler->disassemble(rva);
    }

    if (!disassembled) {
        return false;
    }

    if (!preserves_entry_flags(*disassembled)) {
        return false;
    }

    std::unordered_set<uint64_t> checked_bbs{};

    // track function progressively to find if it pushes flags onto the stack before modifying any
    // and then acquires the lock to classify it as vm entry
    std::optional next_bb_id = disassembled->m_first_bb_id;

    while (next_bb_id.has_value()) {
        const auto &bb = disassembled->m_basic_blocks.at(next_bb_id.value());

        if (checked_bbs.contains(next_bb_id.value())) {
            break;
        }

        checked_bbs.insert(next_bb_id.value());

        // iterate over all instructions of basic block
        for (const auto &instr: bb.m_instructions) {
            if (instr.m_instruction.mnemonic != ZYDIS_MNEMONIC_CMPXCHG) {
                continue;
            }

            if (!(instr.m_instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK)) {
                continue;
            }

            if (instr.m_operands.at(0).type != ZYDIS_OPERAND_TYPE_MEMORY) {
                continue;
            }

            if (disassembled->m_final_block_ids.size() != 1) {
                return false;
            }

            m_known_vm_enters.insert(address);
            return true;
        }

        if (bb.m_successors.size() != 1) {
            break;
        }

        next_bb_id = {bb.m_successors.back()};
    }

    return false;
}

std::shared_ptr<s_themida_vm_handler> c_themida_unpacker::discover_vm_handler(const uint64_t address) {
    const auto image_base = m_memory_manager->get_image_base();
    const auto disassembled = m_disassembler->disassemble(static_cast<uint32_t>(address - image_base));

    if (!disassembled) {
        throw std::runtime_error("themida v3: discover handler: failed to disassemble function");
    }

    if (disassembled->m_final_block_ids.empty()) {
        throw std::runtime_error("themida v3: discover handler: vm handler has no exits");
    }

    const auto vm_handler = std::make_shared<s_themida_vm_handler>(
        address, is_vm_enter(address, disassembled) ? e_themida_handler_type::context_switch :
        e_themida_handler_type::unclassified, disassembled);

    if (disassembled->m_final_block_ids.size() == 1) {
        // create single (terminating) decision point
        vm_handler->m_decision_point = std::make_shared<s_themida_handler_decision_point>(
            image_base + disassembled->m_basic_blocks.at(*disassembled->m_final_block_ids.begin()).m_instructions.back().m_rva);

        return vm_handler;
    }

    // if vm handler / a function has more than 2 final basic blocks, we should have recursive analysis,
    // cba atm, and haven't seen that in binaries so far :)
    if (disassembled->m_final_block_ids.size() != 2) {
        throw std::runtime_error("unthemidator: handler discovery: more than 2 exit bbs");
    }

    std::vector<const c_intel_basic_block *> exit_blocks{};
    for (const auto bb_id: disassembled->m_final_block_ids) {
        exit_blocks.emplace_back(&disassembled->m_basic_blocks.at(bb_id));
    }

    // find the spot where exit paths merge
    const auto common_pred = disassembled->find_common_predecessor(exit_blocks);

    if (!common_pred) {
        throw std::runtime_error("themida v3: discover vm handler: couldn't find VJCC split");
    }

    // branching spot must be cond jmp
    if (common_pred->m_instructions.back().m_instruction.meta.category != ZYDIS_CATEGORY_COND_BR) {
        throw std::runtime_error("themida v3: discover vm handler: unsupported branching spot");
    }

    const auto split_addr = common_pred->m_instructions.back().m_rva + image_base;

    uint64_t branch_fallthrough;
    const auto branch_taken = split_addr + common_pred->m_instructions.back().m_instruction.length;

    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&common_pred->m_instructions.back().m_instruction,
        &common_pred->m_instructions.back().m_operands.at(0), split_addr, &branch_fallthrough))) {
        throw std::runtime_error("themida v3: discover vm handler: unable to find the branch to take");
    }

    // create successors vector
    std::unordered_map<uint64_t, std::shared_ptr<s_themida_handler_decision_point> > successors{};

    // iterate over all successors, find their respective terminators
    for (const std::vector successor_addresses{branch_fallthrough, branch_taken}; const auto addr: successor_addresses) {
        const auto bb_rva = static_cast<uint32_t>(addr - image_base);

        if (!disassembled->m_address_to_bb_id.contains(bb_rva)) {
            throw std::runtime_error("themida v3: discover vm handler: invalid basic block after cond jmp");
        }

        auto last_bb = &disassembled->m_basic_blocks.at(disassembled->m_address_to_bb_id.at(bb_rva));

        // explore until there's a final basic block
        while (!last_bb->m_is_final) {
            if (last_bb->m_successors.empty()) {
                throw std::runtime_error("themida v3: discover vm handler: non-final bb can't have no successors");
            }

            last_bb = &disassembled->m_basic_blocks.at(last_bb->m_successors.back());
        }

        // create exit record
        successors.emplace(addr, std::make_shared<s_themida_handler_decision_point>(image_base +
            last_bb->m_instructions.back().m_rva));
    }

    if (successors.size() != 2) {
        throw std::runtime_error("themida v3: discover vm handler: failed to find all successors");
    }

    vm_handler->m_decision_point = std::make_shared<s_themida_handler_decision_point>(split_addr, successors);

    return vm_handler;
}

void c_themida_unpacker::find_vm_trampolines(const uint64_t base_address, const std::vector<uint8_t> &region, const bool allow_stealth) {
    //
    const auto image_base = m_memory_manager->get_image_base();
    const auto image_end = image_base + m_memory_manager->get_image_size();

    const auto &mapped_image = m_memory_manager->get_mapped_image();

    const auto region_end = base_address + region.size();

    // find all JMP/CALL instructions in the region and check if they're the jumps to VM
    for (size_t i = 0; i < region.size() - 4; i++) {
        if (region.at(i) != 0xE8 && region.at(i) != 0xE9) {
            continue;
        }

        auto rva = *reinterpret_cast<const int32_t *>(region.data() + i + 1);
        auto target_va = static_cast<uint64_t>(rva + static_cast<int64_t>(base_address + i + 5));

        if (target_va < image_base || target_va >= image_end) {
            continue;
        }

        // check if assumed bridge starts with a call, and start disassembling from it if so
        if (mapped_image.at(target_va - image_base) == 0xE8) {
            const auto base = target_va - image_base;

            rva = *reinterpret_cast<const int32_t *>(mapped_image.data() + base + 1);
            target_va = static_cast<uint64_t>(rva + static_cast<int64_t>(image_base + base + 5));

            if (target_va < image_base || target_va >= image_end) {
                continue;
            }
        }

        // target (vm enter) shouldn't be in the same section as prologue unless it's stealth mode
        if (!allow_stealth && target_va >= base_address && target_va < region_end) {
            continue;
        }

        const auto disassembled = m_disassembler->disassemble(static_cast<uint32_t>(
            target_va - image_base), 1500);

        if (!disassembled) {
            continue;
        }

        if (is_vm_enter(target_va, disassembled)) {
            // save vm enter trampoline record
            m_vm_trampolines.emplace_back(s_themida_vm_trampoline{
                .m_trampoline_address = base_address + i,
                .m_vm_enter_address = target_va,
                .m_is_packed = false,
            });

            continue;
        }

        if (!preserves_entry_flags(*disassembled)) {
            continue;
        }

        uint32_t call_count = 0;
        uint32_t proc_state_count = 0;

        // VM is packed when:
        //  in V3, the first basic block of VM enter has a call to the next instruction (call $+5)
        //  in V4, there's a CPUID and XGETBV calls in VM enter
        for (const auto &bb: disassembled->m_basic_blocks) {
            for (const auto &instr: bb.m_instructions) {
                switch (instr.m_instruction.mnemonic) {
                    case ZYDIS_MNEMONIC_CALL:
                        call_count++;
                        break;

                    case ZYDIS_MNEMONIC_XGETBV:
                    case ZYDIS_MNEMONIC_FXSAVE:
                    case ZYDIS_MNEMONIC_FXSAVE64:
                    case ZYDIS_MNEMONIC_XRSTOR:
                    case ZYDIS_MNEMONIC_XRSTOR64:
                    case ZYDIS_MNEMONIC_CPUID:
                        proc_state_count++;
                        break;

                    default:
                        continue;
                }
            }
        }

        if (!m_is_v4) {
            m_is_v4 = proc_state_count >= 4;
        }

        std::optional<uint64_t> dispatch_address = std::nullopt;

        // dispatch to vm enter ends with POPFQ -> RET
        for (const auto bb_id : disassembled->m_final_block_ids) {
            const auto &bb = disassembled->m_basic_blocks.at(bb_id);

            if (bb.m_instructions.size() < 2 || bb.m_instructions.back().m_instruction.mnemonic != ZYDIS_MNEMONIC_RET ||
                ((bb.m_instructions.rbegin() + 1)->m_instruction.mnemonic != ZYDIS_MNEMONIC_POPFQ &&
                (bb.m_instructions.rbegin() + 1)->m_instruction.mnemonic != ZYDIS_MNEMONIC_POPFD)) {
                continue;
            }

            dispatch_address = image_base + bb.m_instructions.back().m_rva;
            break;
        }

        if (!dispatch_address.has_value()) {
            continue;
        }

        // save vm enter trampoline record
        m_vm_trampolines.emplace_back(s_themida_vm_trampoline{
            .m_trampoline_address = base_address + i,
            .m_vm_enter_address = target_va,
            .m_is_packed = call_count >= 2,
            .m_dispatch_address = dispatch_address.value(),
        });
    }
}

bool c_themida_unpacker::recover_import(const uint64_t entry_address) {
    if (!m_updated_pointers.contains(entry_address)) {
        return false;
    }

    const auto original_value = m_updated_pointers.at(entry_address);
    const uint64_t final_value = m_pe_image->get_ptr_size() == 4 ? m_emulator_ctx->read<uint32_t>(entry_address).value() :
        m_emulator_ctx->read<uint64_t>(entry_address).value();

    // if final address corresponds to known import, we can identify the module and the function immediately
    const auto *known_fn = m_emulator_ctx->get_imports()->find_import_by_address(final_value);

    if (!known_fn) {
        if (final_value < m_loader_region->first || final_value >= m_loader_region->second) {
            return false;
        }

        // disassemble potential import call stub
        const auto disassembled = m_disassembler->disassemble(final_value - m_memory_manager->get_image_base());

        if (!disassembled) {
            return false;
        }

        // first stub's instruction must either be a JMP or a PUSH
        if (const auto &first_bb = disassembled->m_basic_blocks.at(disassembled->m_first_bb_id);
            first_bb.m_instructions.empty() || (first_bb.m_instructions.front().m_instruction.mnemonic != ZYDIS_MNEMONIC_JMP &&
                first_bb.m_instructions.front().m_instruction.mnemonic != ZYDIS_MNEMONIC_PUSH)) {
            //
            return false;
        }

        // if the import address is obfuscated, emulate the call until the int3 instruction
        // we already have breakpoints set on all potential addresses
        try {
            m_emulator_ctx->run(final_value, 0);
        } catch (...) {
            return false;
        }

        known_fn = m_emulator_ctx->get_imports()->find_import_by_address(m_emulator_ctx->get_pc());
    }

    if (!known_fn) {
        return false;
    }

    m_recovered_imports.emplace_back(s_themida_recovered_import{
        .m_iat_rva = static_cast<uint32_t>(entry_address - m_memory_manager->get_image_base()),
        .m_ordinal = known_fn->m_ordinal,
        .m_is_ordinal = (m_pe_image->is_x64() && original_value & unthemidator::pe::k_ordinal_flag_64 &&
            original_value >> 52 == 0x800) || known_fn->m_name.length() < 2,
        .m_module = known_fn->m_module,
        .m_function = known_fn->m_name,
    });

    return true;
}
