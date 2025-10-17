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
        // Required size for the handle
        constexpr uint32_t required_size = sizeof(handle);
        char dummy;
        
        // Condition 1: NULL buffer check (STATUS_ACCESS_VIOLATION)
        // If buffer is NULL but length is not 0, return access violation immediately
        if (process_information == 0 && process_information_length != 0)
        {
            // Do NOT write return_length here - immediate error
            return STATUS_ACCESS_VIOLATION; // 0xC0000005
        }
        
        // Condition 2a: Check for alignment BEFORE size check (important!)
        // If buffer is not aligned to pointer size, return misalignment
        if (process_information != 0 && process_information % sizeof(void*) != 0)
        {
            // Do NOT write return_length here - alignment error takes precedence
            return STATUS_DATATYPE_MISALIGNMENT; // 0x80000002
        }
        
        // Condition 2b: Wrong buffer size check (STATUS_INFO_LENGTH_MISMATCH)
        // Check buffer size mismatch
        if (process_information_length < required_size)
        {
            // Write return_length ONLY for INFO_LENGTH_MISMATCH and if address is valid
            if (return_length)
            {
                if (c.win_emu.memory.try_read_memory(return_length.value(), &dummy, 1))
                {
                    return_length.write(required_size);
                }
                else
                {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
            return STATUS_INFO_LENGTH_MISMATCH; // 0xC0000004
        }
        
        // Condition 3: Valid call - check if process is being debugged
        const auto debug_obj_handle = c.proc.debug_objects.get_first_handle();
        
        // Check for overlapping buffers (anti-anti-debug detection)
        // If return_length points to the same location as process_information,
        // we need to write return_length FIRST, then check if we should overwrite with handle
        const bool overlapping_buffers = (return_length && return_length.value() == process_information);
        
        if (overlapping_buffers)
        {
            // CRITICAL: Write return_length FIRST for overlapping buffer case
            if (c.win_emu.memory.try_read_memory(return_length.value(), &dummy, 1))
            {
                return_length.write(required_size);
            }
            else
            {
                return STATUS_ACCESS_VIOLATION;
            }
            
            // Now check if we're being debugged
            if (debug_obj_handle.bits != NULL_HANDLE.bits)
            {
                // Being debugged: overwrite with the debug object handle
                const emulator_object<handle> debug_handle{c.emu, process_information};
                debug_handle.write(debug_obj_handle);
                return STATUS_SUCCESS; // 0x00000000
            }
            else
            {
                // NOT being debugged: leave the return_length value (don't overwrite)
                // The buffer now contains required_size, which is correct behavior
                return STATUS_PORT_NOT_SET; // 0xC0000353
            }
        }
        else
        {
            // Normal case: non-overlapping buffers
            // Write return_length first (if valid address)
            // CRITICAL: Write return_length FIRST for overlapping buffer case
            if (c.win_emu.memory.try_read_memory(return_length.value(), &dummy, 1))
            {
                return_length.write(required_size);
            }
            
            // Then write the handle value
            const emulator_object<handle> debug_handle{c.emu, process_information};
            
            if (debug_obj_handle.bits != NULL_HANDLE.bits)
            {
                // Process IS being debugged, return the debug object handle
                debug_handle.write(debug_obj_handle);
                return STATUS_SUCCESS; // 0x00000000
            }
            else
            {
                // Process is NOT being debugged, return NULL handle
                debug_handle.write(NULL_HANDLE);
                return STATUS_PORT_NOT_SET; // 0xC0000353
            }
        }
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
                                                 const uint32_t system_information_length, [[maybe_unused]] const emulator_object<uint32_t> return_length)
    {

        SYSTEM_FIRMWARE_TABLE_INFORMATION table_info{};

        // Try to read the input buffer if it exists and has sufficient length
        if (input_buffer && input_buffer_length >= sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION))
        {
            table_info = c.emu.read_memory<SYSTEM_FIRMWARE_TABLE_INFORMATION>(input_buffer);
        }
        else
        {
            // GetSystemFirmwareTable calls NtQuerySystemInformation with input_buffer containing SYSTEM_FIRMWARE_TABLE_INFORMATION
            // But sometimes input_buffer is NULL, default to Get action for SMBIOS data
            table_info.ProviderSignature = RSMB_SIGNATURE;
            table_info.Action = SystemFirmwareTableGet; // Default to Get for SMBIOS data
            table_info.TableID = 0x0000; // Default SMBIOS table ID
            table_info.TableBufferLength = system_information_length; // Use provided buffer length
        }

        // Handle RSMB (Raw SMBIOS) signature
        if (table_info.ProviderSignature == RSMB_SIGNATURE)
        {
            // IMPORTANT: Check TableID - only support TableID 0 for SMBIOS
            if (table_info.TableID != 0)
            {
                return STATUS_NOT_SUPPORTED;
            }

            if (table_info.Action == SystemFirmwareTableEnumerate)
            {

                return STATUS_NOT_SUPPORTED;
            }
            else if (table_info.Action == SystemFirmwareTableGet)
            {

                // (RawSMBIOSData format for compatibility with provided code)
                // Increased buffer size for more tables
                std::vector<uint8_t> tableData(16384); // Larger buffer for comprehensive SMBIOS data

                uint8_t* tablePtr = tableData.data();
                uint16_t handleCounter = 0;

                // Type 0: BIOS Information
                SMBIOS_BIOS_INFORMATION* bios = (SMBIOS_BIOS_INFORMATION*)tablePtr;
                bios->Type = 0;
                bios->Length = 24;
                bios->Handle = handleCounter++;
                bios->Vendor = 1; // String index
                bios->BIOSVersion = 2;
                bios->BIOSStartingAddressSegment = 0xE800;
                bios->BIOSReleaseDate = 3;
                bios->BIOSROMSize = 16; // 16*64KB = 1MB
                bios->BIOSCharacteristics = 0x0800000000000000ULL; // Supports UEFI
                bios->BIOSCharacteristicsExtensionBytes = 0x0003;
                bios->SystemBIOSMajorRelease = 2;
                bios->SystemBIOSMinorRelease = 7;
                bios->EmbeddedControllerFirmwareMajorRelease = 0xFF;
                bios->EmbeddedControllerFirmwareMinorRelease = 0xFF;
                tablePtr += 24;

                // Type 1: System Information
                SMBIOS_SYSTEM_INFORMATION* sys = (SMBIOS_SYSTEM_INFORMATION*)tablePtr;
                sys->Type = 1;
                sys->Length = 27;
                sys->Handle = handleCounter++;
                sys->Manufacturer = 1;
                sys->ProductName = 2;
                sys->Version = 3;
                sys->SerialNumber = 4;
                memset(sys->UUID, 0xFF, 16); // Invalid UUID for VM
                sys->WakeUpType = 6; // Power Switch
                sys->SKUNumber = 5;
                sys->Family = 6;
                tablePtr += 27;

                // Type 2: Base Board Information
                SMBIOS_BASEBOARD_INFORMATION* board = (SMBIOS_BASEBOARD_INFORMATION*)tablePtr;
                board->Type = 2;
                board->Length = 15;
                board->Handle = handleCounter++;
                board->Manufacturer = 1;
                board->Product = 2;
                board->Version = 3;
                board->SerialNumber = 4;
                board->AssetTag = 5;
                board->FeatureFlags = 0x09; // Hosting board, replaceable
                board->LocationInChassis = 1;
                board->ChassisHandle = handleCounter + 1; // Next handle will be chassis
                board->BoardType = 10; // Motherboard
                board->NumberOfContainedObjectHandles = 0;
                tablePtr += 15;

                // Type 3: Chassis Information
                // Simplified chassis structure
                *tablePtr++ = 3; // Type
                *tablePtr++ = 21; // Length
                *tablePtr++ = handleCounter & 0xFF; *tablePtr++ = (handleCounter >> 8) & 0xFF; handleCounter++; // Handle
                *tablePtr++ = 1; // Manufacturer
                *tablePtr++ = 2; // Type (Desktop)
                *tablePtr++ = 3; // Version
                *tablePtr++ = 4; // Serial Number
                *tablePtr++ = 5; // Asset Tag
                *tablePtr++ = 2; // Boot-up State (Safe)
                *tablePtr++ = 2; // Power Supply State (Safe)
                *tablePtr++ = 2; // Thermal State (Safe)
                *tablePtr++ = 2; // Security Status (Unknown)
                *tablePtr++ = 0; *tablePtr++ = 0; *tablePtr++ = 0; *tablePtr++ = 0; // OEM defined
                *tablePtr++ = 1; // Height
                *tablePtr++ = 0; // Number of Power Cords

                // Type 4: Processor Information (multiple processors)
                for(int proc = 0; proc < 4; proc++) {
                    SMBIOS_PROCESSOR_INFORMATION* processor = (SMBIOS_PROCESSOR_INFORMATION*)tablePtr;
                    processor->Type = 4;
                    processor->Length = 42;
                    processor->Handle = handleCounter++;
                    processor->SocketDesignation = 1;
                    processor->ProcessorType = 3; // Central Processor
                    processor->ProcessorFamily = 0xC6; // Core i7 equivalent
                    processor->ProcessorManufacturer = 2;
                    processor->ProcessorID = 0x123456789ABCDEF0ULL;
                    processor->ProcessorVersion = 3;
                    processor->Voltage = 0x80; // 1.2V
                    processor->ExternalClock = 100;
                    processor->MaxSpeed = 4000;
                    processor->CurrentSpeed = 3500;
                    processor->Status = 0x41; // Enabled, CPU Socket Populated
                    processor->ProcessorUpgrade = 1; // Other
                    tablePtr += 42;
                }

                // Type 7: Cache Information (multiple caches)
                for(int cache = 0; cache < 6; cache++) {
                    SMBIOS_CACHE_INFORMATION* cacheInfo = (SMBIOS_CACHE_INFORMATION*)tablePtr;
                    cacheInfo->Type = 7;
                    cacheInfo->Length = 19;
                    cacheInfo->Handle = handleCounter++;
                    cacheInfo->SocketDesignation = 1;
                    cacheInfo->CacheConfiguration = 0x0180; // Enabled, Not Socketed
                    cacheInfo->MaximumCacheSize = 8192; // 8MB
                    cacheInfo->InstalledSize = 8192;
                    cacheInfo->SupportedSRAMType = 0x0004; // Synchronous
                    cacheInfo->CurrentSRAMType = 0x0004;
                    tablePtr += 19;
                }

                // Type 8: Port Connector Information (multiple ports)
                for(int port = 0; port < 8; port++) {
                    SMBIOS_PORT_CONNECTOR_INFORMATION* portInfo = (SMBIOS_PORT_CONNECTOR_INFORMATION*)tablePtr;
                    portInfo->Type = 8;
                    portInfo->Length = 9;
                    portInfo->Handle = handleCounter++;
                    portInfo->InternalReferenceDesignator = 1;
                    portInfo->InternalConnectorType = 0x0A; // RJ-45
                    portInfo->ExternalReferenceDesignator = 2;
                    portInfo->ExternalConnectorType = 0x0A; // RJ-45
                    portInfo->PortType = 0x1D; // Network Port
                    tablePtr += 9;
                }

                // Type 9: System Slots (multiple slots)
                for(int slot = 0; slot < 6; slot++) {
                    SMBIOS_SYSTEM_SLOT* slotInfo = (SMBIOS_SYSTEM_SLOT*)tablePtr;
                    slotInfo->Type = 9;
                    slotInfo->Length = 13;
                    slotInfo->Handle = handleCounter++;
                    slotInfo->SlotDesignation = 1;
                    slotInfo->SlotType = 0x0D; // PCI Express
                    slotInfo->SlotDataBusWidth = 0x0E; // x16
                    slotInfo->CurrentUsage = 1; // Available
                    slotInfo->SlotLength = 3; // Short
                    slotInfo->SlotID = static_cast<uint16_t>(slot);
                    slotInfo->SlotCharacteristics1 = 0x0A; // PME signal, SMBus signal
                    tablePtr += 13;
                }

                // Type 10: On Board Devices Information
                for(int device = 0; device < 5; device++) {
                    SMBIOS_ONBOARD_DEVICES* deviceInfo = (SMBIOS_ONBOARD_DEVICES*)tablePtr;
                    deviceInfo->Type = 10;
                    deviceInfo->Length = 6;
                    deviceInfo->Handle = handleCounter++;
                    deviceInfo->DeviceType = 0x0A | (0x01 << 7); // Ethernet, enabled
                    deviceInfo->DescriptionString = static_cast<uint8_t>(device + 1);
                    tablePtr += 6;
                }

                // Type 11: OEM Strings
                SMBIOS_OEM_STRINGS* oem = (SMBIOS_OEM_STRINGS*)tablePtr;
                oem->Type = 11;
                oem->Length = 5;
                oem->Handle = handleCounter++;
                oem->Count = 3;
                tablePtr += 5;

                // Type 12: System Configuration Options
                SMBIOS_SYSTEM_CONFIGURATION_OPTIONS* config = (SMBIOS_SYSTEM_CONFIGURATION_OPTIONS*)tablePtr;
                config->Type = 12;
                config->Length = 5;
                config->Handle = handleCounter++;
                config->Count = 2;
                tablePtr += 5;

                // Type 13: BIOS Language Information
                SMBIOS_BIOS_LANGUAGE* lang = (SMBIOS_BIOS_LANGUAGE*)tablePtr;
                lang->Type = 13;
                lang->Length = 22;
                lang->Handle = handleCounter++;
                lang->InstallableLanguages = 1;
                lang->Flags = 0;
                memset(lang->Reserved, 0, 15);
                lang->CurrentLanguage = 1;
                tablePtr += 22;

                // Type 14: Group Associations (multiple groups)
                for(int group = 0; group < 3; group++) {
                    SMBIOS_GROUP_ASSOCIATIONS* groupInfo = (SMBIOS_GROUP_ASSOCIATIONS*)tablePtr;
                    groupInfo->Type = 14;
                    groupInfo->Length = 5;
                    groupInfo->Handle = handleCounter++;
                    groupInfo->GroupName = 1;
                    groupInfo->ItemType = 0;
                    groupInfo->ItemHandle = 0;
                    tablePtr += 5;
                }

                // Type 15: System Event Log
                SMBIOS_SYSTEM_EVENT_LOG* eventLog = (SMBIOS_SYSTEM_EVENT_LOG*)tablePtr;
                eventLog->Type = 15;
                eventLog->Length = 23;
                eventLog->Handle = handleCounter++;
                eventLog->LogAreaLength = 0;
                eventLog->LogHeaderStartOffset = 0;
                eventLog->LogDataStartOffset = 0;
                eventLog->AccessMethod = 0;
                eventLog->LogStatus = 0;
                eventLog->LogChangeToken = 0;
                eventLog->AccessMethodAddress = 0;
                eventLog->LogHeaderFormat = 0;
                eventLog->NumberOfSupportedLogTypeDescriptors = 0;
                eventLog->LengthOfLogTypeDescriptor = 0;
                tablePtr += 23;

                // Type 16: Physical Memory Array
                SMBIOS_PHYSICAL_MEMORY_ARRAY* memArray = (SMBIOS_PHYSICAL_MEMORY_ARRAY*)tablePtr;
                memArray->Type = 16;
                memArray->Length = 15;
                memArray->Handle = handleCounter++;
                memArray->Location = 0x03;  // System board
                memArray->Use = 0x03;       // System memory
                memArray->MemoryErrorCorrection = 0x06;  // None
                memArray->MaximumCapacity = 0x00200000;  // 8GB in KB
                memArray->MemoryErrorInformationHandle = 0xFFFE;
                memArray->NumberOfMemoryDevices = 2;
                tablePtr += 15;

                // Type 17: Memory Device (multiple devices)
                for(int mem = 0; mem < 2; mem++) {
                    SMBIOS_MEMORY_DEVICE* memDevice = (SMBIOS_MEMORY_DEVICE*)tablePtr;
                    memDevice->Type = 17;
                    memDevice->Length = 34; // Extended for DDR4
                    memDevice->Handle = handleCounter++;
                    memDevice->PhysicalMemoryArrayHandle = handleCounter - 2; // Reference to memory array
                    memDevice->MemoryErrorInformationHandle = 0xFFFE;
                    memDevice->TotalWidth = 64;
                    memDevice->DataWidth = 64;
                    memDevice->Size = 0x1000;  // 4096 MB
                    memDevice->FormFactor = 0x09;  // DIMM
                    memDevice->DeviceSet = static_cast<uint8_t>(mem);
                    memDevice->DeviceLocator = 1;
                    memDevice->BankLocator = 2;
                    memDevice->MemoryType = 0x1A;  // DDR4
                    memDevice->TypeDetail = 0x0080;
                    memDevice->Speed = 2133;
                    memDevice->Manufacturer = 3;
                    memDevice->SerialNumber = 4;
                    memDevice->AssetTag = 5;
                    memDevice->PartNumber = 6;
                    memDevice->Attributes = 0;
                    memDevice->ExtendedSize = 0;
                    memDevice->ConfiguredMemoryClockSpeed = 2133;
                    tablePtr += 34;
                }

                // Add more dummy tables to reach 40+ total tables
                // Types 18-126: Various SMBIOS structures
                for(int type = 18; type < 127; type++) {
                    if(type == 127) break; // End marker
                    uint8_t dummyLength = 8; // Minimum structure size
                    *tablePtr++ = static_cast<uint8_t>(type);
                    *tablePtr++ = dummyLength;
                    *tablePtr++ = static_cast<uint8_t>(handleCounter & 0xFF);
                    *tablePtr++ = static_cast<uint8_t>((handleCounter >> 8) & 0xFF);
                    handleCounter++;
                    // Fill remaining bytes with zeros
                    for(int i = 3; i < dummyLength; i++) {
                        *tablePtr++ = 0;
                    }
                    // String terminator
                    *tablePtr++ = 0;
                }

                // Now add all the strings at the end
                const char* allStrings[] = {
                    "American Megatrends Inc.", "07/15/2023", "A.B0", "System Manufacturer", "System Product Name",
                    "System Version", "System Serial Number", "SKU Number", "Family", "To Be Filled By O.E.M.",
                    "Intel(R) Corporation", "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz", "LGA1151", "CPU Internal L2",
                    "CPU Internal L1", "Ethernet Controller", "USB Controller", "SATA Controller", "Audio Controller",
                    "VGA Controller", "Manufacturer", "DIMM_A1", "BANK 0", "BANK 1", "Manufacturer", "12345678",
                    "AssetTag", "PartNumber", "BANK 2", "BANK 3", "BANK 4", "BANK 5", "BANK 6", "BANK 7",
                    "BANK 8", "BANK 9", "BANK 10", "BANK 11", "BANK 12", "BANK 13", "BANK 14", "BANK 15",
                    nullptr
                };

                for(int i = 0; allStrings[i]; i++) {
                    strcpy((char*)tablePtr, allStrings[i]);
                    tablePtr += strlen(allStrings[i]) + 1;
                }
                *tablePtr++ = 0;  // Final string terminator

                // Type 127: End of Table
                *tablePtr++ = 127;
                *tablePtr++ = 4;
                *tablePtr++ = 0;
                *tablePtr++ = 0;
                *tablePtr++ = 0;
                *tablePtr++ = 0;

                uint32_t tableDataLength = (uint32_t)(tablePtr - tableData.data());

                // RawSMBIOSData structure
                struct RawSMBIOSData {
                    BYTE method;       // Access method (obsolete)
                    BYTE mjVer;        // Major version
                    BYTE mnVer;        // Minor version
                    BYTE dmiRev;       // DMI revision (obsolete)
                    DWORD length;      // Table data size
                    BYTE tableData[1]; // Variable table data
                };

                RawSMBIOSData raw{};
                raw.method = 0;
                raw.mjVer = 2;
                raw.mnVer = 7;
                raw.dmiRev = 0;
                raw.length = tableDataLength;

                const size_t required_size = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) - 1 + sizeof(RawSMBIOSData) - 1 + tableDataLength;

                if (return_length)
                {
                    return_length.write(static_cast<ULONG>(required_size));
                }

                if (system_information_length < required_size)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                SYSTEM_FIRMWARE_TABLE_INFORMATION output_struct{};
                output_struct.ProviderSignature = table_info.ProviderSignature;
                output_struct.Action = table_info.Action;
                output_struct.TableID = table_info.TableID;
                output_struct.TableBufferLength = sizeof(RawSMBIOSData) - 1 + tableDataLength;

                write_memory_with_callback(c, system_information, &output_struct, sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) - 1);
                write_memory_with_callback(c, system_information + sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) - 1, &raw, sizeof(RawSMBIOSData) - 1);
                write_memory_with_callback(c, system_information + sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION) - 1 + sizeof(RawSMBIOSData) - 1, tableData.data(), tableDataLength);

                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS handle_SystemLicenseInformation(const syscall_context& c, const uint64_t system_information,
                                             const uint32_t system_information_length, const emulator_object<uint32_t> return_length)
    {
        return handle_query<SYSTEM_LICENSE_INFORMATION>(c, system_information, system_information_length, return_length,
                                                         [&](SYSTEM_LICENSE_INFORMATION& license_info) {
                                                             license_info.LicenseStatus = 0; // SL_GEN_STATE_IS_GENUINE
                                                             license_info.LicenseType = 1;   // Genuine license
                                                         });
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

   BOOL power_capabilities()
   {

       SYSTEM_POWER_CAPABILITIES powerCaps{};
       // In a real system, this would call GetPwrCapabilities(&powerCaps)
       // For anti-debug bypass, we return power capabilities that make it look like a VM

       powerCaps.PowerButtonPresent = TRUE;
       powerCaps.SleepButtonPresent = TRUE;
       powerCaps.LidPresent = TRUE;
       powerCaps.SystemS1 = FALSE;  // VMs don't support S1
       powerCaps.SystemS2 = FALSE;  // VMs don't support S2
       powerCaps.SystemS3 = FALSE;  // VMs don't support S3
       powerCaps.SystemS4 = FALSE;  // VMs don't support S4
       powerCaps.SystemS5 = TRUE;
       powerCaps.HiberFilePresent = FALSE;
       powerCaps.FullWake = TRUE;
       powerCaps.VideoDimPresent = TRUE;
       powerCaps.ApmPresent = FALSE;
       powerCaps.UpsPresent = FALSE;
       powerCaps.ThermalControl = FALSE;  // VMs usually don't have thermal control
       powerCaps.ProcessorThrottle = TRUE;
       powerCaps.ProcessorMinThrottle = 0;
       powerCaps.ProcessorMaxThrottle = 100;
       powerCaps.FastSystemS4 = FALSE;
       powerCaps.DiskSpinDown = TRUE;
       powerCaps.SystemBatteriesPresent = FALSE;

       // The anti-debug check: if S1-S4 are all FALSE and ThermalControl is FALSE, it's considered a VM
       if ((powerCaps.SystemS1 | powerCaps.SystemS2 | powerCaps.SystemS3 | powerCaps.SystemS4) == FALSE) {
           return (powerCaps.ThermalControl == FALSE);
       }

       return FALSE;
   }

   NTSTATUS handle_QueryKeyCachedInformation(const syscall_context& c, const uint64_t key_information, const ULONG length,
                                             const emulator_object<ULONG> result_length, const handle key_handle)
   {
       constexpr auto required_size = sizeof(KEY_CACHED_INFORMATION);
       result_length.write(required_size);

       if (length < required_size)
       {
           return STATUS_BUFFER_TOO_SMALL;
       }

       // Return fake cached information to bypass anti-debug detection
       // This provides information that looks like a real registry key
       KEY_CACHED_INFORMATION info{};
       info.LastWriteTime.QuadPart = 0;
       info.TitleIndex = 0;
       info.SubKeys = 10;  // Fake number of subkeys
       info.MaxNameLen = 100;  // Fake max name length
       info.Values = 5;  // Fake number of values
       info.MaxValueNameLen = 50;  // Fake max value name length
       info.MaxValueDataLen = 1024;  // Fake max value data length
       info.NameLength = static_cast<ULONG>((key_handle == 0 ? 0 : 1) * 2);  // Fake name length

       const emulator_object<KEY_CACHED_INFORMATION> info_obj{c.emu, key_information};
       info_obj.write(info);

       return STATUS_SUCCESS;
   }

   NTSTATUS handle_SystemPowerCapabilities(const syscall_context& c, const uint64_t output_buffer, const ULONG output_buffer_length)
   {
       if (output_buffer_length < sizeof(SYSTEM_POWER_CAPABILITIES))
       {
           return STATUS_BUFFER_TOO_SMALL;
       }

       // Return fake power capabilities to bypass anti-debug detection
       // VMs typically don't support S1-S4 sleep states and thermal control
       SYSTEM_POWER_CAPABILITIES caps{};
       memset(&caps, 0, sizeof(caps));
       caps.PowerButtonPresent = TRUE;
       caps.SleepButtonPresent = TRUE;
       caps.LidPresent = TRUE;
       caps.SystemS1 = FALSE;  // VMs don't support S1
       caps.SystemS2 = FALSE;  // VMs don't support S2
       caps.SystemS3 = FALSE;  // VMs don't support S3
       caps.SystemS4 = FALSE;  // VMs don't support S4
       caps.SystemS5 = TRUE;
       caps.HiberFilePresent = FALSE;
       caps.FullWake = TRUE;
       caps.VideoDimPresent = TRUE;
       caps.ApmPresent = FALSE;
       caps.UpsPresent = FALSE;
       caps.ThermalControl = FALSE;  // VMs usually don't have thermal control
       caps.ProcessorThrottle = TRUE;
       caps.ProcessorMinThrottle = 0;
       caps.ProcessorMaxThrottle = 100;
       caps.FastSystemS4 = FALSE;
       caps.DiskSpinDown = TRUE;
       caps.SystemBatteriesPresent = FALSE;
       caps.BatteriesAreShortTerm = FALSE;
       // BatteryScale and other fields can be zero for simplicity

       write_memory_with_callback(c, output_buffer, &caps, sizeof(caps));
       return STATUS_SUCCESS;
   }

   // Timer-related anti-debug bypass
   struct TIMER_SET_INFORMATION
   {
       LARGE_INTEGER DueTime;
       LONG Period;
       uint64_t CompletionRoutine;
       uint64_t CompletionContext;
       BOOLEAN Resume;
   };

   NTSTATUS handle_NtSetTimerEx(const syscall_context& c, handle timer_handle, uint32_t timer_set_info_class,
                                 uint64_t timer_set_information, ULONG timer_set_information_length)
   {
       (void)timer_set_information_length;

       if (timer_set_info_class != 0) // TimerSetInformationClass
       {
           return STATUS_INVALID_PARAMETER;
       }

       auto* t = c.proc.timers.get(timer_handle);
       if (!t)
       {
           return STATUS_INVALID_HANDLE;
       }

       emulator_object<TIMER_SET_INFORMATION> set_info(c.emu, timer_set_information);
       if (!set_info)
       {
           return STATUS_INVALID_PARAMETER;
       }

       const auto info = set_info.read();
       const auto delay_interval = info.DueTime;

       t->due_time = utils::convert_delay_interval_to_time_point(c.win_emu.clock(), delay_interval);
       t->signaled = false;
       t->period = static_cast<uint32_t>(info.Period);

       if (info.CompletionRoutine)
       {
           c.win_emu.current_thread().pending_apcs.push_back({0, info.CompletionRoutine, info.CompletionContext, WM_TIMER, 0});
       }

       return STATUS_SUCCESS;
   }
}