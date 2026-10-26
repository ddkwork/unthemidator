cmake_minimum_required(VERSION 4.0)
project(unthemidator LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(project_warnings INTERFACE)

if(MSVC)
    target_compile_options(project_warnings INTERFACE
            /W4
            /permissive-
    )

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(project_warnings INTERFACE
                /clang:-Wno-c++98-compat
                /clang:-Wno-c++98-compat-pedantic
        )
    endif()
else()
    target_compile_options(project_warnings INTERFACE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wshadow
    )
endif()

set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)

set(UNICORN_ARCH "x86" CACHE STRING "Enabled unicorn architectures" FORCE)
set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory(dependencies/zydis)
add_subdirectory(dependencies/unicorn)

add_executable(unthemidator
        src/main.cpp
        src/helpers/common.hpp
        src/pe/pe_structs.hpp
        src/pe/c_pe_image.cpp
        src/pe/c_pe_image.hpp
        src/memory/c_memory.cpp
        src/memory/c_memory.hpp
        src/memory/c_memory_manager.cpp
        src/memory/c_memory_manager.hpp
        src/emulator/c_emulator_ctx.cpp
        src/emulator/c_emulator_ctx.hpp
        src/emulator/c_emulator.cpp
        src/emulator/c_emulator.hpp
        src/emulator/windows.hpp
        src/unpacker/c_themida_unpacker.cpp
        src/unpacker/c_themida_unpacker.hpp
        src/unpacker/c_loader_generator.cpp
        src/unpacker/c_loader_generator.hpp
        src/disassembler/c_intel_function.hpp
        src/disassembler/c_intel_disassembler.cpp
        src/disassembler/c_intel_disassembler.hpp
        src/unpacker/s_themida_instruction.hpp
        src/unpacker/themida_structs.hpp
        src/unpacker/c_themida_unpacker_emu.cpp
        src/emulator/wl_hooks.cpp
        src/emulator/hooks.cpp
        src/emulator/hooks.hpp
        src/pe/pe_utils.cpp
        src/pe/pe_utils.hpp
        src/disassembler/c_intel_function.cpp
        src/pe/c_pe_builder.cpp
        src/pe/c_pe_builder.hpp
        src/emulator/c_imports.cpp
        src/emulator/c_imports.hpp
)

target_include_directories(unthemidator PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(unthemidator PRIVATE
        Zydis
        unicorn
        project_warnings
)

target_compile_features(unthemidator PRIVATE cxx_std_20)

set_target_properties(unthemidator PROPERTIES
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
)

add_custom_command(TARGET unthemidator POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/static"
        "$<TARGET_FILE_DIR:unthemidator>"
        COMMENT "Copying static files..."
)
