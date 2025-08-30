#include "anti_debug.hpp"
#include "windows_emulator.hpp"
#include "windows_objects.hpp"
#include "syscall_utils.hpp"
#include "memory_utils.hpp"
#include <utils/string.hpp>

namespace
{
    bool ends_with_ignore_case(const std::u16string& str, const std::u16string_view suffix)
    {
        if (str.length() < suffix.length())
        {
            return false;
        }
        return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin(),
                          [](char16_t a, char16_t b) { return std::tolower(a) == std::tolower(b); });
    }
}

namespace anti_debug
{

    std::u16string normalize_path(const syscall_context& c, std::u16string_view path)
    {
        constexpr std::u16string_view system_root_prefix = u"\\SystemRoot";
        if (utils::string::starts_with_ignore_case(path, system_root_prefix))
        {
            const std::u16string_view system_root = c.proc.kusd.get().NtSystemRoot.arr;
            return std::u16string(system_root) + std::u16string(path.substr(system_root_prefix.size()));
        }

        return std::u16string(path);
    }

    NTSTATUS handle_ProcessDebugObjectHandle(const syscall_context& c, const uint64_t process_information,
                                             const uint32_t process_information_length,
                                             const emulator_object<uint32_t> return_length)
    {
        return handle_query<handle>(c.emu, process_information, process_information_length, return_length,
                                    [](handle& h) {
                                        h = NULL_HANDLE;
                                        return STATUS_PORT_NOT_SET;
                                    });
    }

    NTSTATUS handle_ProcessDebugFlags(const syscall_context& c, const uint64_t process_information,
                                      const uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_query<ULONG>(c.emu, process_information, process_information_length, return_length,
                                   [&](ULONG& res) {
                                       res = 0; // Not being debugged
                                   });
    }

    NTSTATUS handle_ProcessDebugPort(const syscall_context& c, const uint64_t process_information,
                                     const uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_query<EmulatorTraits<Emu64>::PVOID>(
            c.emu, process_information, process_information_length, return_length,
            [](EmulatorTraits<Emu64>::PVOID& ptr) {
                ptr = 0; // No debug port
            });
    }
    
    NTSTATUS handle_NtCreateDebugObject(const syscall_context& c, const emulator_object<handle> debug_object_handle,
                                        const ACCESS_MASK /*desired_access*/,
                                        const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> /*object_attributes*/,
                                        const ULONG /*flags*/)
    {
        // For now, just return a dummy pseudo-handle to satisfy the anti-debug check.
        // NtClose can handle pseudo-handles correctly.
        (void)c;
        debug_object_handle.write(make_pseudo_handle(1, handle_types::debug_object));
        return STATUS_SUCCESS;
    }
}