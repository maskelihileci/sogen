#pragma once
#include "std_include.hpp"
#include "emulator_utils.hpp"
#include "windows_objects.hpp"
#include "syscall_utils.hpp"

namespace anti_debug
{
    std::u16string normalize_path(const syscall_context& c, std::u16string_view path);

    NTSTATUS handle_ProcessDebugObjectHandle(const syscall_context& c, uint64_t process_information,
                                             uint32_t process_information_length,
                                             const emulator_object<uint32_t> return_length);

    NTSTATUS handle_ProcessDebugFlags(const syscall_context& c, uint64_t process_information,
                                      uint32_t process_information_length, const emulator_object<uint32_t> return_length);

    NTSTATUS handle_ProcessDebugPort(const syscall_context& c, uint64_t process_information,
                                     uint32_t process_information_length, const emulator_object<uint32_t> return_length);
    NTSTATUS handle_NtCreateDebugObject(const syscall_context& c, emulator_object<handle> debug_object_handle,
                                        ACCESS_MASK desired_access,
                                        emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes, ULONG flags);
}