#pragma once
#include "std_include.hpp"
#include "emulator_utils.hpp"
#include "windows_objects.hpp"
#include "syscall_utils.hpp"

#define STATUS_NO_YIELD_PERFORMED 0x40000024

namespace anti_debug
{
    enum SYSTEM_FIRMWARE_TABLE_ACTION
    {
        SystemFirmwareTableEnumerate = 0,
         SystemFirmwareTableGet = 1,
    };

    struct SYSTEM_FIRMWARE_TABLE_INFORMATION
    {
        ULONG ProviderSignature;
        SYSTEM_FIRMWARE_TABLE_ACTION Action;
        ULONG TableID;
        ULONG TableBufferLength;
        UCHAR TableBuffer[1]; // Variable size
    };

    struct SYSTEM_MEMORY_USAGE_INFORMATION
    {
        ULONGLONG TotalPhysicalBytes;
        ULONGLONG AvailableBytes;
        LONGLONG ResidentAvailableBytes;
        ULONGLONG CommittedBytes;
        ULONGLONG SharedCommittedBytes;
        ULONGLONG CommitLimitBytes;
        ULONGLONG PeakCommitmentBytes;
    };

    // Simple SMBIOS data for memory detection bypass
    const uint8_t smbios_data[] = {
        // SMBIOS Entry Point Structure (EPS) 2.0
        '_', 'S', 'M', '_',           // Anchor
        0x00,                         // Checksum (calculated below)
        0x1F,                         // Length
        0x02,                         // Major Version
        0x06,                         // Minor Version
        0xFF, 0xFF,                   // Max Structure Size
        0x00,                         // Entry Point Revision
        0x00, 0x00, 0x00, 0x00, 0x00, // Formatted Area
        '_', 'D', 'M', 'I', '_',       // Intermediate Anchor
        0x00,                         // Intermediate Checksum (calculated below)
        0x00, 0x00,                   // Table Length (calculated below)
        0x00, 0x00, 0x00, 0x00,       // Table Address (calculated below)
        0x00, 0x00,                   // Number of Structures
        0x26,                         // BCD Revision

        // Type 16: Physical Memory Array
        16,                           // Type
        15,                           // Length
        0x00, 0x00,                   // Handle
        0x01,                         // Location: Other
        0x03,                         // Use: System Memory
        0x06,                         // Memory Error Correction: Not Applicable
        0x00, 0x00, 0x20, 0x00,       // Maximum Capacity: 8GB (in KB)
        0xFE, 0xFF,                   // Memory Error Information Handle
        0x01,                         // Number of Memory Devices

        // Type 17: Memory Device
        17,                           // Type
        28,                           // Length
        0x01, 0x00,                   // Handle
        0x00, 0x00,                   // Memory Array Handle
        0xFE, 0xFF,                   // Memory Error Information Handle
        64, 0,                        // Total Width
        64, 0,                        // Data Width
        0x00, 0x20,                   // Size: 8192 MB
        0x09,                         // Form Factor: DIMM
        0x00,                         // Device Set
        'D', 'I', 'M', 'M', 0, 0, 0, 0, 0, 0, 0, 0, // Device Locator
        'B', 'A', 'N', 'K', ' ', '0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Bank Locator
        0x1A,                         // Memory Type: DDR4
        0x80, 0x00,                   // Type Detail
        0x55, 0x08,                   // Speed: 2133 MT/s
        'M', 'a', 'n', 'u', 'f', 'a', 'c', 't', 'u', 'r', 'e', 'r', 0, 0, 0, 0, // Manufacturer
        '1', '2', '3', '4', '5', '6', '7', '8', 0, 0, 0, 0, 0, 0, 0, 0, // Serial Number
        'A', 's', 's', 'e', 't', 'T', 'a', 'g', 0, 0, 0, 0, 0, 0, 0, 0, // Asset Tag
        'P', 'a', 'r', 't', 'N', 'u', 'm', 'b', 'e', 'r', 0, 0, 0, 0, 0, 0, // Part Number
        0x00,                         // Attributes
        0x00, 0x00, 0x00, 0x00,       // Extended Size
        0x55, 0x08,                   // Configured Memory Clock Speed
    };    

struct SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID64 ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING<EmulatorTraits<Emu64>> ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    ULONG_PTR PeakVirtualSize;
    ULONG_PTR VirtualSize;
    ULONG PageFaultCount;
    ULONG_PTR PeakWorkingSetSize;
    ULONG_PTR WorkingSetSize;
    ULONG_PTR QuotaPeakPagedPoolUsage;
    ULONG_PTR QuotaPagedPoolUsage;
    ULONG_PTR QuotaPeakNonPagedPoolUsage;
    ULONG_PTR QuotaNonPagedPoolUsage;
    ULONG_PTR PagefileUsage;
    ULONG_PTR PeakPagefileUsage;
    ULONG_PTR PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
};

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
    NTSTATUS handle_SystemExtendedProcessInformation(const syscall_context& c, uint64_t system_information,
                                                     uint32_t system_information_length,
                                                     const emulator_object<uint32_t> return_length);

    NTSTATUS handle_ProcessIoCounters(const syscall_context& c, uint64_t process_information,
                                      uint32_t process_information_length, const emulator_object<uint32_t> return_length);
    NTSTATUS handle_NtSetInformationThread_ThreadHideFromDebugger(
        const syscall_context& c, const handle thread_handle, uint64_t thread_information, uint32_t thread_information_length);

    NTSTATUS handle_NtYieldExecution();

    NTSTATUS handle_NtQueryInformationThread_ThreadHideFromDebugger(
        const syscall_context& c, const handle thread_handle, uint64_t thread_information,
        uint32_t thread_information_length, const emulator_object<uint32_t> return_length);

    void handle_int2d_exception(windows_emulator& win_emu);
    void ObjectTypeInformation(const syscall_context& c, const handle object_handle, OBJECT_TYPE_INFORMATION& info);
    NTSTATUS handle_ProcessImageFileName(const syscall_context& c, uint32_t info_class, uint64_t process_information,
                                         uint32_t process_information_length, const emulator_object<uint32_t> return_length);
    NTSTATUS handle_ProcessQuotaLimits(const syscall_context& c, uint64_t process_information,
                                      uint32_t process_information_length, const emulator_object<uint32_t> return_length);
    NTSTATUS handle_ProcessVmCounters(const syscall_context& c, uint64_t process_information,
                                     uint32_t process_information_length, const emulator_object<uint32_t> return_length);
    NTSTATUS handle_SystemMemoryUsageInformation(const syscall_context& c, const uint64_t system_information,
                                                 const uint32_t system_information_length, const emulator_object<uint32_t> return_length);
    NTSTATUS handle_SystemFirmwareTableInformation(const syscall_context& c, const uint64_t input_buffer,
                                                   const uint32_t input_buffer_length, const uint64_t system_information,
                                                   const uint32_t system_information_length, const emulator_object<uint32_t> return_length);
}