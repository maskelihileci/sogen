#pragma once
#include "std_include.hpp"
#include "emulator_utils.hpp"
#include "windows_objects.hpp"
#include "syscall_utils.hpp"

namespace anti_debug
{

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
}