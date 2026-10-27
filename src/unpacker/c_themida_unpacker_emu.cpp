#include <iostream>

#include "c_themida_unpacker.hpp"

#include "../helpers/utils.hpp"

void c_themida_unpacker::run_virtual_instruction(const uint64_t address) {
    if (!m_vm_handlers.contains(address)) {
        m_vm_handlers.emplace(address, discover_vm_handler(address));
    }

    const auto image_base = m_memory_manager->get_image_base();
    const auto &vm_handler = m_vm_handlers.at(address);

    if (vm_handler->m_type == e_themida_handler_type::context_switch) {
        if (!run_vm_entry_setup(address)) {
            throw std::runtime_error("failed to run VM enter (context switch handler)");
        }

        // if VM enter's depth exceeds max allowed nested instances, run emulation of ALL instances that are deeper
        // in one emulation cycle instead of by virtual instruction
        if (m_options.m_max_nested_vms == 0 || m_vm_instances.size() < m_options.m_max_nested_vms + 1) {
            return;
        }

        std::cout << "[unthemidator][vm] emulating VM (depth=" << m_vm_instances.size() << ")..." << std::endl;

        const auto is_vm_active_address = m_vm_instances.back()->m_vm_ctx + m_vm_instances.back()->m_is_in_vm_offset;
        uint64_t run_until = 0;

        m_emulator_ctx->run(m_emulator_ctx->get_pc(), run_until, nullptr,
            [&](uc_engine* uc, const uc_mem_type mem_type, const uint64_t addr,
                const int, const int64_t value) -> void {
                //
                if (mem_type != UC_MEM_WRITE) {
                    return;
                }

                if (value != 0) {
                    return;
                }

                if (addr != is_vm_active_address) {
                    return;
                }

                const auto disassembled = m_disassembler->disassemble(
                    static_cast<uint32_t>(m_emulator_ctx->get_pc() - image_base));

                if (!disassembled || disassembled->m_final_block_ids.size() != 1) {
                    throw std::runtime_error("bad function - can't disassemble to return from vm exit handler");
                }

                uc_emu_stop(uc);
                run_until = image_base + disassembled->m_basic_blocks.at(
                    *disassembled->m_final_block_ids.begin()).m_instructions.rbegin()->m_rva;
            });

        // after catching vm_ctx->is_active update, run emulation until handler end
        m_emulator_ctx->run(m_emulator_ctx->get_pc(), run_until);

        // single step onto the next instruction
        m_emulator_ctx->single_step();

        // after VM exit, pop the VM instance
        m_vm_instances.pop_back();

        std::cout << "[unthemidator][vm] exited child VM" << std::endl;
        return;
    }

    bool exited_vm = false;
    std::function<mem_callback_t> on_mem = nullptr;

    // track vm exits if there's an active vm instance
    if (!m_vm_instances.empty()) {
        const auto &vm_instance = m_vm_instances.back();

        on_mem = [&exited_vm, vm_instance](uc_engine*, const uc_mem_type mem_type, const uint64_t addr, const int,
            const int64_t value) -> void {
            //
            if (mem_type != UC_MEM_WRITE || addr != vm_instance->m_vm_ctx + vm_instance->m_is_in_vm_offset) {
                return;
            }

            exited_vm = value == 0;
        };
    }

    std::vector worklist{ std::make_pair(address, vm_handler->m_decision_point) };

    // run execution until the next decision point in a handler
    while (!worklist.empty()) {
        const auto [start_address, decision_point] = worklist.back();
        worklist.pop_back();

        m_emulator_ctx->run(start_address, decision_point->m_address, nullptr, on_mem);

        // if current decision point is not terminating, single step onto the taken branch and continue
        if (!decision_point->m_terminating) {
            // single step onto the next path
            m_emulator_ctx->single_step();

            // get new decision point
            const auto it_next_dec_point = decision_point->m_successors.find(m_emulator_ctx->get_pc());

            if (it_next_dec_point == decision_point->m_successors.end()) {
                throw std::runtime_error("damn... unexpected decision point");
            }

            worklist.emplace_back(it_next_dec_point->first, it_next_dec_point->second);
            continue;
        }

        // single step onto the next handler / function
        m_emulator_ctx->single_step();
        break;
    }

    if (exited_vm) {
        // last vm instance is no longer active past vm exit
        m_vm_instances.pop_back();
    }
}

bool c_themida_unpacker::run_vm_entry_setup(const uint64_t address) {
    const auto &vm_handler = m_vm_handlers.at(address);
    const auto &disassembled = vm_handler->m_disassembled;

    std::optional<uint64_t> vm_enter_sync;
    std::unordered_set<ZydisRegister> potential_vm_ctx_regs{};

    // find virtualization start point
    for (const auto &bb : disassembled->m_basic_blocks) {
        for (const auto &insn : bb.m_instructions) {
            if (insn.m_instruction.mnemonic != ZYDIS_MNEMONIC_CMPXCHG) {
                continue;
            }

            if (!(insn.m_instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK)) {
                continue;
            }

            vm_enter_sync = m_memory_manager->get_image_base() + insn.m_rva;

            // log potential VM context registers
            for (const auto &operand : insn.m_operands) {
                if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY) {
                    continue;
                }

                if (operand.mem.base != ZYDIS_REGISTER_NONE) {
                    potential_vm_ctx_regs.insert(operand.mem.base);
                }

                if (operand.mem.index != ZYDIS_REGISTER_NONE) {
                    potential_vm_ctx_regs.insert(operand.mem.index);
                }
            }

            m_is_multi_vm = false;

            // get fallthrough successor basic block
            auto successors = bb.m_successors;
            const auto target_bb_rva = static_cast<uint32_t>(bb.m_instructions.back().m_branch_target);

            if (!disassembled->m_address_to_bb_id.contains(target_bb_rva)) {
                break;
            }

            std::erase(successors, disassembled->m_address_to_bb_id.at(target_bb_rva));

            if (successors.size() != 1) {
                break;
            }

            // analyze fallthrough bb instructions to find counter DEC/INC instruction indicating multiple vCPU support
            for (const auto& fallthrough_insn : disassembled->m_basic_blocks.at(
                successors.at(0)).m_instructions) {
                //
                if (fallthrough_insn.m_instruction.mnemonic != ZYDIS_MNEMONIC_INC &&
                    fallthrough_insn.m_instruction.mnemonic != ZYDIS_MNEMONIC_DEC) {
                    //
                    continue;
                }

                m_is_multi_vm = true;
                break;
            }

            break;
        }
    }

    // if vm entry synchronization wasn't found, we're most likely not dealing with Themida
    if (!vm_enter_sync.has_value()) {
        return false;
    }

    // runtime VM enter must have exactly 1 final basic block (dispatch to first virtual instruction)
    if (disassembled->m_final_block_ids.size() != 1) {
        throw std::runtime_error("startup: unexpected VM enter structure");
    }

    // run emulation until VM context synchronization
    m_emulator_ctx->run(address, vm_enter_sync.value());

    const auto vm_instance = std::make_shared<themida_structs>();

    // find vm context ptr register and the vm ctx address itself
    for (const auto reg : potential_vm_ctx_regs) {
        const auto reg_value = m_emulator_ctx->get_x86_reg_value(utils::get_emulator_reg(reg));

        if (reg_value < m_memory_manager->get_image_base() ||
            reg_value >= m_memory_manager->get_image_base() + m_memory_manager->get_image_size()) {
            //
            continue;
        }

        vm_instance->m_vm_ctx_register = reg;
        vm_instance->m_vm_ctx = reg_value;

        break;
    }

    // single step onto the next instruction, figure out is_in_vm field's offset
    m_emulator_ctx->single_step([&](uc_engine*, const uc_mem_type, const uint64_t addr, const int, const int64_t) -> void {
        vm_instance->m_is_in_vm_offset = static_cast<uint32_t>(addr - vm_instance->m_vm_ctx);
    });

    // run until jmp to the first vm handler
    m_emulator_ctx->run(m_emulator_ctx->get_pc(), m_memory_manager->get_image_base() +
        disassembled->m_basic_blocks.at(*disassembled->m_final_block_ids.begin()).m_instructions.back().m_rva);

    // single step onto the first vm handler
    m_emulator_ctx->single_step();

    m_vm_instances.push_back(vm_instance);
    return true;
}

void c_themida_unpacker::run_decompression_stub(const s_themida_vm_trampoline &trampoline) const {
    // run emulation until the dispatcher instruction
    m_emulator_ctx->run(trampoline.m_trampoline_address, trampoline.m_dispatch_address);

    // single step onto the vm enter
    m_emulator_ctx->single_step();

    // save all sections including the section(s) containing now unpacked VM
    for (const auto &section : m_pe_image->get_sections()) {
        const auto address = m_memory_manager->get_image_base() + section.virtual_address;

        std::vector<uint8_t> region_dump(section.virtual_size, 0);
        uc_mem_read(m_emulator_ctx->get_uc(), address, region_dump.data(), region_dump.size());
        m_memory_manager->write_memory(address, region_dump);
    }
}
