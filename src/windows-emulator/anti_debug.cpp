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

    uint8_t calculate_checksum(const uint8_t* data, size_t length)
    {
        uint8_t sum = 0;
        for (size_t i = 0; i < length; ++i)
        {
            sum += data[i];
        }
        return -sum;
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

    NTSTATUS handle_NtYieldExecution()
    {
        return STATUS_NO_YIELD_PERFORMED;
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

    NTSTATUS handle_ProcessImageFileName(const syscall_context& c, const uint32_t info_class, const uint64_t process_information,
                                         const uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        const auto* mod = c.win_emu.mod_manager.executable;
        if (!mod)
        {
            return STATUS_UNSUCCESSFUL;
        }

        std::u16string path_str;
        if (info_class == ProcessImageFileName)
        {
            // NT Path: \Device\HarddiskVolumeX\path\to\file.exe
            path_str = windows_path(mod->path).to_device_path();
        }
        else
        {
            // Win32 Path: C:\path\to\file.exe
            path_str = mod->path.u16string();
        }

        const auto required_size = sizeof(UNICODE_STRING<EmulatorTraits<Emu64>>) + (path_str.size() + 1) * sizeof(char16_t);

        if (return_length)
        {
            return_length.write(static_cast<uint32_t>(required_size));
        }

        if (process_information_length < required_size)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        const auto buffer_start = process_information + sizeof(UNICODE_STRING<EmulatorTraits<Emu64>>);
        write_memory_with_callback(c, buffer_start, path_str.c_str(), (path_str.size() + 1) * sizeof(char16_t));

        const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> info{c.emu, process_information};
        info.access([&](UNICODE_STRING<EmulatorTraits<Emu64>>& str) {
            str.Length = static_cast<USHORT>(path_str.size() * sizeof(char16_t));
            str.MaximumLength = static_cast<USHORT>((path_str.size() + 1) * sizeof(char16_t));
            str.Buffer = buffer_start;
        });

        return STATUS_SUCCESS;
    }

    NTSTATUS handle_SystemMemoryUsageInformation(const syscall_context& c, const uint64_t system_information,
                                                 const uint32_t system_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_query<SYSTEM_MEMORY_USAGE_INFORMATION>(c, system_information, system_information_length, return_length,
                                                            [&](SYSTEM_MEMORY_USAGE_INFORMATION& info) {
                                                                info.TotalPhysicalBytes = 8ULL * 1024 * 1024 * 1024; // 8GB
                                                                info.AvailableBytes = 7ULL * 1024 * 1024 * 1024; // 7GB
                                                                info.ResidentAvailableBytes = 6LL * 1024 * 1024 * 1024; // 6GB
                                                                info.CommittedBytes = 2ULL * 1024 * 1024 * 1024; // 2GB
                                                                info.SharedCommittedBytes = 1ULL * 1024 * 1024 * 1024; // 1GB
                                                                info.CommitLimitBytes = 8ULL * 1024 * 1024 * 1024; // 8GB
                                                                info.PeakCommitmentBytes = 3ULL * 1024 * 1024 * 1024; // 3GB
                                                            });
    }

    NTSTATUS handle_SystemFirmwareTableInformation(const syscall_context& c, const uint64_t input_buffer,
                                                   const uint32_t input_buffer_length, const uint64_t system_information,
                                                   const uint32_t system_information_length, const emulator_object<uint32_t> return_length)
    {
        if (!input_buffer || input_buffer_length != sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION))
        {
            return STATUS_INVALID_PARAMETER;
        }

        SYSTEM_FIRMWARE_TABLE_INFORMATION request_data{};
        const auto mem_data = c.emu.read_memory(input_buffer, sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION));
        memcpy(&request_data, mem_data.data(), sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION));

        if (request_data.ProviderSignature != 0x424D5352) // 'RSMB' for SMBIOS
        {
            return STATUS_NOT_SUPPORTED;
        }

        if (request_data.Action != SystemFirmwareTableGet)
        {
            return STATUS_NOT_SUPPORTED;
        }

        if (request_data.TableID != 0)
        {
            return STATUS_NOT_SUPPORTED;
        }

        const size_t eps_size = 0x1F;
        const size_t table_size = sizeof(smbios_data) - eps_size;
        const size_t total_size = eps_size + table_size;

        if (return_length)
        {
            return_length.write(static_cast<ULONG>(total_size));
        }

        if (system_information_length < total_size)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }

        // Copy EPS
        uint8_t eps[0x1F];
        memcpy(eps, smbios_data, eps_size);

        // Calculate checksums
        eps[4] = calculate_checksum(eps, 0x10); // EPS checksum
        eps[5] = 0x1F; // Length already set
        // Update table length and address
        const uint16_t table_len = static_cast<uint16_t>(table_size);
        eps[0x16] = table_len & 0xFF;
        eps[0x17] = (table_len >> 8) & 0xFF;
        const uint32_t table_addr = system_information + eps_size;
        eps[0x18] = table_addr & 0xFF;
        eps[0x19] = (table_addr >> 8) & 0xFF;
        eps[0x1A] = (table_addr >> 16) & 0xFF;
        eps[0x1B] = (table_addr >> 24) & 0xFF;
        eps[0x1C] = 2; // Number of structures (Type 16 and 17)
        eps[0x1D] = 0;

        // Intermediate checksum
        eps[0x11] = calculate_checksum(eps + 0x10, 0x0F);

        write_memory_with_callback(c, system_information, eps, eps_size);

        // Copy table data
        write_memory_with_callback(c, system_information + eps_size, smbios_data + eps_size, table_size);

        return STATUS_SUCCESS;
    }

    NTSTATUS handle_ProcessQuotaLimits(const syscall_context& c, uint64_t process_information,
                                       uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        struct QUOTA_LIMITS {
            SIZE_T PagedPoolLimit;
            SIZE_T NonPagedPoolLimit;
            SIZE_T MinimumWorkingSetSize;
            SIZE_T MaximumWorkingSetSize;
            SIZE_T PagefileLimit;
            LARGE_INTEGER TimeLimit;
        };

        return handle_query<QUOTA_LIMITS>(c, process_information, process_information_length, return_length,
                                          [&](QUOTA_LIMITS& limits) {
                                              limits.PagedPoolLimit = 0;
                                              limits.NonPagedPoolLimit = 0;
                                              limits.MinimumWorkingSetSize = 0;
                                              limits.MaximumWorkingSetSize = 0;
                                              limits.PagefileLimit = 0;
                                              limits.TimeLimit.QuadPart = 0;
                                          });
    }

    NTSTATUS handle_ProcessVmCounters(const syscall_context& c, uint64_t process_information,
                                      uint32_t process_information_length, const emulator_object<uint32_t> return_length)
    {
        struct VM_COUNTERS {
            SIZE_T PeakVirtualSize;
            SIZE_T VirtualSize;
            ULONG PageFaultCount;
            SIZE_T PeakWorkingSetSize;
            SIZE_T WorkingSetSize;
            SIZE_T QuotaPeakPagedPoolUsage;
            SIZE_T QuotaPagedPoolUsage;
            SIZE_T QuotaPeakNonPagedPoolUsage;
            SIZE_T QuotaNonPagedPoolUsage;
            SIZE_T PagefileUsage;
            SIZE_T PeakPagefileUsage;
            SIZE_T PrivateUsage;
        };

        return handle_query<VM_COUNTERS>(c, process_information, process_information_length, return_length,
                                         [&](VM_COUNTERS& counters) {
                                             counters.PeakVirtualSize = 0;
                                             counters.VirtualSize = 0;
                                             counters.PageFaultCount = 0;
                                             counters.PeakWorkingSetSize = 0;
                                             counters.WorkingSetSize = 0;
                                             counters.QuotaPeakPagedPoolUsage = 0;
                                             counters.QuotaPagedPoolUsage = 0;
                                             counters.QuotaPeakNonPagedPoolUsage = 0;
                                             counters.QuotaNonPagedPoolUsage = 0;
                                             counters.PagefileUsage = 0;
                                             counters.PeakPagefileUsage = 0;
                                             counters.PrivateUsage = 0;
                                         });
    }
}