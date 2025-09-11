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
        return handle_query<handle>(c, process_information, process_information_length, return_length,
                                    [](handle& h) {
                                        h = NULL_HANDLE;
                                        return STATUS_PORT_NOT_SET;
                                    });
    }

    NTSTATUS handle_ProcessDebugFlags(const syscall_context& c, const uint64_t process_information,
                                      const uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_query<ULONG>(c, process_information, process_information_length, return_length,
                                   [&](ULONG& res) {
                                       res = 0; // Not being debugged
                                       return STATUS_PORT_NOT_SET;
                                   });
    }

    NTSTATUS handle_ProcessDebugPort(const syscall_context& c, const uint64_t process_information,
                                     const uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_query<EmulatorTraits<Emu64>::PVOID>(
            c, process_information, process_information_length, return_length,
            [](EmulatorTraits<Emu64>::PVOID& ptr) {
                ptr = 0; // No debug port
            });
    }
    
    NTSTATUS handle_NtCreateDebugObject(const syscall_context& c, const emulator_object<handle> debug_object_handle,
                                        const ACCESS_MASK /*desired_access*/,
                                        const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> /*object_attributes*/,
                                        const ULONG /*flags*/)
    {
        // Create a real debug object to be tracked by the handle store.
        debug_object obj{};
        const auto new_handle = c.proc.debug_objects.store(std::move(obj));
        debug_object_handle.write(new_handle);
        return STATUS_SUCCESS;
    }
    NTSTATUS handle_SystemExtendedProcessInformation(const syscall_context& c, const uint64_t system_information,
                                                     const uint32_t system_information_length,
                                                     const emulator_object<uint32_t> return_length)
    {
        // This bypasses a check that iterates a process list and compares counters.
        const size_t required_size = sizeof(SYSTEM_PROCESS_INFORMATION);

        if (return_length)
        {
            return_length.write(static_cast<ULONG>(required_size));
        }

        if (system_information_length < required_size)
        {
            return STATUS_INFO_LENGTH_MISMATCH; // 0xC0000004
        }

        SYSTEM_PROCESS_INFORMATION info{};
        info.NextEntryOffset = 0; // Terminate the list
        info.NumberOfThreads = static_cast<ULONG>(c.proc.threads.size());
        if (c.proc.active_thread && c.proc.active_thread->teb.has_value())
        {
            info.UniqueProcessId = reinterpret_cast<HANDLE>(c.proc.active_thread->teb->read().ClientId.UniqueProcess);
        }
        else
        {
            info.UniqueProcessId = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(c.proc.id));
        }
        info.InheritedFromUniqueProcessId = reinterpret_cast<HANDLE>(0);



        write_memory_with_callback(c, system_information, info);

        return STATUS_SUCCESS;
    }
    NTSTATUS handle_ProcessIoCounters(const syscall_context& c, const uint64_t process_information,
                                      const uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_query<IO_COUNTERS>(c, process_information, process_information_length, return_length,
                                        [](IO_COUNTERS& counters) {
                                            memset(&counters, 0, sizeof(counters));
                                            // Set a consistent, non-zero value for the counters to match system.cpp
                                            counters.ReadOperationCount = 0;
                                            counters.WriteOperationCount = 0;
                                            counters.OtherOperationCount = 0;
                                            counters.ReadTransferCount = 0;
                                            counters.WriteTransferCount = 0;
                                            counters.OtherTransferCount = 0;
                                        });
   }
   NTSTATUS handle_NtSetInformationThread_ThreadHideFromDebugger(
        const syscall_context& c, const handle thread_handle, const uint64_t thread_information,
        const uint32_t thread_information_length)
    {
        auto* thread = thread_handle == CURRENT_THREAD ? c.proc.active_thread : c.proc.threads.get(thread_handle);
        if (!thread)
        {
            return STATUS_INVALID_HANDLE;
        }

        if (thread_information != 0 || thread_information_length != 0)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        thread->is_hidden_from_debugger = true;
        c.win_emu.callbacks.on_suspicious_activity("Hiding thread from debugger");
        return STATUS_SUCCESS;
    }

    NTSTATUS handle_NtQueryInformationThread_ThreadHideFromDebugger(
        const syscall_context& c, const handle thread_handle, const uint64_t thread_information,
        const uint32_t thread_information_length, const emulator_object<uint32_t> return_length)
    {
        const auto* thread = thread_handle == CURRENT_THREAD ? c.proc.active_thread : c.proc.threads.get(thread_handle);
        if (!thread)
        {
            return STATUS_INVALID_HANDLE;
        }
        
        if (thread_information % 4 != 0)
        {
            return STATUS_DATATYPE_MISALIGNMENT;
        }

        if (thread_information_length != sizeof(BOOLEAN))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (return_length)
        {
            return_length.write(sizeof(BOOLEAN));
        }

        const emulator_object<BOOLEAN> info{c.emu, thread_information};
        info.write(thread->is_hidden_from_debugger);

        return STATUS_SUCCESS;
    }
    void handle_int2d_exception(windows_emulator& win_emu)
    {
        const uint64_t current_ip = win_emu.current_thread().current_ip;
        try
        {
            const auto instruction = win_emu.emu().read_memory<uint16_t>(current_ip);
            if (instruction == 0x2DCD) // int 2dh
            {
                // On a real CPU, the IP is advanced *before* the interrupt is handled.
                // We need to replicate this behavior to avoid an infinite loop.
                win_emu.current_thread().current_ip += 2;
            }
        }
        catch (const std::exception&)
        {
            // Failed to read, proceed with normal breakpoint dispatch.
        }
    }

    void ObjectTypeInformation(const syscall_context& c, const handle object_handle, OBJECT_TYPE_INFORMATION& info)
    {
    size_t count = 0;
    switch (static_cast<handle_types::type>(object_handle.value.type))
    {
    case handle_types::file:
        count = c.proc.files.size();
        break;
    case handle_types::device:
        count = c.proc.devices.size();
        break;
    case handle_types::event:
        count = c.proc.events.size();
        break;
    case handle_types::section:
        count = c.proc.sections.size();
        break;
    case handle_types::semaphore:
        count = c.proc.semaphores.size();
        break;
    case handle_types::port:
        count = c.proc.ports.size();
        break;
    case handle_types::thread:
        count = c.proc.threads.size();
        break;
    case handle_types::registry:
        count = c.proc.registry_keys.size();
        break;
    case handle_types::mutant:
        count = c.proc.mutants.size();
        break;
    case handle_types::window:
        count = c.proc.windows.size();
        break;
    case handle_types::timer:
        count = c.proc.timers.size();
        break;
    case handle_types::debug_object:
        count = c.proc.debug_objects.size();
        break;
    default:
        break;
    }
    info.TotalNumberOfObjects = static_cast<ULONG>(count);
    info.TotalNumberOfHandles = static_cast<ULONG>(count); // Simplification: assume 1 handle per object

    }
}