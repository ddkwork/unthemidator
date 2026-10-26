#ifndef UNTHEMIDATOR_HOOKS_HPP
#define UNTHEMIDATOR_HOOKS_HPP

#include "c_emulator_ctx.hpp"

namespace hooks {

    void get_module_handle(const c_emulator_ctx *ctx);
    void get_proc_address(const c_emulator_ctx *ctx);
    void create_file_a(const c_emulator_ctx *ctx);
    void create_file_w(const c_emulator_ctx *ctx);
    void create_file_mapping(const c_emulator_ctx *ctx);
    void rtl_allocate_heap(const c_emulator_ctx *ctx);
    void rtl_reallocate_heap(const c_emulator_ctx *ctx);
    void rtl_free_heap(const c_emulator_ctx *ctx);
    void local_alloc(const c_emulator_ctx *ctx);
    void get_current_dir(const c_emulator_ctx *ctx);
    void get_adapters_info(const c_emulator_ctx *ctx);
    void sh_get_special_folder_path_w(const c_emulator_ctx *ctx);
    void get_volume_information_a(const c_emulator_ctx *ctx);
    void get_local_time(const c_emulator_ctx *ctx);
    void system_time_to_file_time(const c_emulator_ctx *ctx);
    void get_module_filename(const c_emulator_ctx *ctx);
    void get_command_line_a(const c_emulator_ctx *ctx);
    void get_command_line_w(const c_emulator_ctx *ctx);
    void add_veh(c_emulator_ctx *ctx);
    void remove_veh(c_emulator_ctx *ctx);
    void raise_exception(c_emulator_ctx *ctx);
    void get_version(const c_emulator_ctx *ctx);
    void virtual_alloc(const c_emulator_ctx *ctx);
    void virtual_free(const c_emulator_ctx *ctx);
    void virtual_protect(const c_emulator_ctx *ctx);
    void map_view_of_file(const c_emulator_ctx *ctx);
    void get_file_size(const c_emulator_ctx *ctx);
    void get_token_information(const c_emulator_ctx *ctx);
    void get_thread_context(const c_emulator_ctx *ctx);
    void create_thread(const c_emulator_ctx *ctx);

    void message_box_ex_w(const c_emulator_ctx *ctx);
    void message_box_ex_a(const c_emulator_ctx *ctx);

    void nt_query_information_process(const c_emulator_ctx *ctx);
    void nt_query_system_information(const c_emulator_ctx *ctx);
    void nt_protect_virtual_memory(const c_emulator_ctx *ctx);
    void nt_query_object(const c_emulator_ctx *ctx);
    void check_remote_debugger(const c_emulator_ctx *ctx);
    void is_wow64_process(const c_emulator_ctx *ctx);
    void is_wow64_process2(const c_emulator_ctx *ctx);
    void get_current_process_id(const c_emulator_ctx *ctx);
    void get_current_thread_id(const c_emulator_ctx *ctx);
    void get_last_error(const c_emulator_ctx *ctx);
    void set_last_error(const c_emulator_ctx *ctx);
    void create_toolhelp_snapshot(const c_emulator_ctx *ctx);
    void close_handle(const c_emulator_ctx *ctx);
    void process_next_w(const c_emulator_ctx *ctx);
    void process_first(const c_emulator_ctx *ctx);
    void process_first_w(const c_emulator_ctx *ctx);
    void process_next(const c_emulator_ctx *ctx);

    void dummy_function(const c_emulator_ctx *ctx);
    void dummy_true_function(const c_emulator_ctx *ctx);

    void vm_enter(const c_emulator_ctx *ctx);

}

#endif //UNTHEMIDATOR_HOOKS_HPP
