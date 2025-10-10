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

    const ULONG RSMB_SIGNATURE = 0x52534D42; // 'R' 'S' 'M' 'B' in little endian

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

struct SMBIOS_PHYSICAL_MEMORY_ARRAY {
    uint8_t Type;                // 16
    uint8_t Length;              // 15
    uint16_t Handle;
    uint8_t Location;
    uint8_t Use;
    uint8_t MemoryErrorCorrection;
    uint32_t MaximumCapacity;
    uint16_t MemoryErrorInformationHandle;
    uint16_t NumberOfMemoryDevices;
};

struct SMBIOS_MEMORY_DEVICE {
    uint8_t Type;                // 17
    uint8_t Length;              // 28+
    uint16_t Handle;
    uint16_t PhysicalMemoryArrayHandle;
    uint16_t MemoryErrorInformationHandle;
    uint16_t TotalWidth;
    uint16_t DataWidth;
    uint16_t Size;
    uint8_t FormFactor;
    uint8_t DeviceSet;
    uint8_t DeviceLocator;
    uint8_t BankLocator;
    uint8_t MemoryType;
    uint16_t TypeDetail;
    uint16_t Speed;
    uint8_t Manufacturer;
    uint8_t SerialNumber;
    uint8_t AssetTag;
    uint8_t PartNumber;
    uint8_t Attributes;
    uint32_t ExtendedSize;
    uint16_t ConfiguredMemoryClockSpeed;
};

// Additional SMBIOS structures for anti-debug bypass
struct SMBIOS_BIOS_INFORMATION {
    uint8_t Type;                // 0
    uint8_t Length;              // 18+
    uint16_t Handle;
    uint8_t Vendor;
    uint8_t BIOSVersion;
    uint16_t BIOSStartingAddressSegment;
    uint8_t BIOSReleaseDate;
    uint8_t BIOSROMSize;
    uint64_t BIOSCharacteristics;
    uint16_t BIOSCharacteristicsExtensionBytes;
    uint8_t SystemBIOSMajorRelease;
    uint8_t SystemBIOSMinorRelease;
    uint8_t EmbeddedControllerFirmwareMajorRelease;
    uint8_t EmbeddedControllerFirmwareMinorRelease;
};

struct SMBIOS_SYSTEM_INFORMATION {
    uint8_t Type;                // 1
    uint8_t Length;              // 27
    uint16_t Handle;
    uint8_t Manufacturer;
    uint8_t ProductName;
    uint8_t Version;
    uint8_t SerialNumber;
    uint8_t UUID[16];
    uint8_t WakeUpType;
    uint8_t SKUNumber;
    uint8_t Family;
};

struct SMBIOS_BASEBOARD_INFORMATION {
    uint8_t Type;                // 2
    uint8_t Length;              // 15+
    uint16_t Handle;
    uint8_t Manufacturer;
    uint8_t Product;
    uint8_t Version;
    uint8_t SerialNumber;
    uint8_t AssetTag;
    uint8_t FeatureFlags;
    uint8_t LocationInChassis;
    uint16_t ChassisHandle;
    uint8_t BoardType;
    uint8_t NumberOfContainedObjectHandles;
};

struct SMBIOS_PROCESSOR_INFORMATION {
    uint8_t Type;                // 4
    uint8_t Length;              // 26+
    uint16_t Handle;
    uint8_t SocketDesignation;
    uint8_t ProcessorType;
    uint8_t ProcessorFamily;
    uint8_t ProcessorManufacturer;
    uint64_t ProcessorID;
    uint8_t ProcessorVersion;
    uint8_t Voltage;
    uint16_t ExternalClock;
    uint16_t MaxSpeed;
    uint16_t CurrentSpeed;
    uint8_t Status;
    uint8_t ProcessorUpgrade;
};

struct SMBIOS_CACHE_INFORMATION {
    uint8_t Type;                // 7
    uint8_t Length;              // 19
    uint16_t Handle;
    uint8_t SocketDesignation;
    uint16_t CacheConfiguration;
    uint16_t MaximumCacheSize;
    uint16_t InstalledSize;
    uint16_t SupportedSRAMType;
    uint16_t CurrentSRAMType;
};

struct SMBIOS_PORT_CONNECTOR_INFORMATION {
    uint8_t Type;                // 8
    uint8_t Length;              // 9
    uint16_t Handle;
    uint8_t InternalReferenceDesignator;
    uint8_t InternalConnectorType;
    uint8_t ExternalReferenceDesignator;
    uint8_t ExternalConnectorType;
    uint8_t PortType;
};

struct SMBIOS_SYSTEM_SLOT {
    uint8_t Type;                // 9
    uint8_t Length;              // 13
    uint16_t Handle;
    uint8_t SlotDesignation;
    uint8_t SlotType;
    uint8_t SlotDataBusWidth;
    uint8_t CurrentUsage;
    uint8_t SlotLength;
    uint16_t SlotID;
    uint8_t SlotCharacteristics1;
};

struct SMBIOS_ONBOARD_DEVICES {
    uint8_t Type;                // 10
    uint8_t Length;              // 6
    uint16_t Handle;
    uint8_t DeviceType;
    uint8_t DescriptionString;
};

struct SMBIOS_OEM_STRINGS {
    uint8_t Type;                // 11
    uint8_t Length;              // 5
    uint16_t Handle;
    uint8_t Count;
};

struct SMBIOS_SYSTEM_CONFIGURATION_OPTIONS {
    uint8_t Type;                // 12
    uint8_t Length;              // 5
    uint16_t Handle;
    uint8_t Count;
};

struct SMBIOS_BIOS_LANGUAGE {
    uint8_t Type;                // 13
    uint8_t Length;              // 22
    uint16_t Handle;
    uint8_t InstallableLanguages;
    uint8_t Flags;
    uint8_t Reserved[15];
    uint8_t CurrentLanguage;
};

struct SMBIOS_GROUP_ASSOCIATIONS {
    uint8_t Type;                // 14
    uint8_t Length;              // 5
    uint16_t Handle;
    uint8_t GroupName;
    uint16_t ItemType;
    uint16_t ItemHandle;
};

struct SMBIOS_SYSTEM_EVENT_LOG {
    uint8_t Type;                // 15
    uint8_t Length;              // 23
    uint16_t Handle;
    uint16_t LogAreaLength;
    uint16_t LogHeaderStartOffset;
    uint16_t LogDataStartOffset;
    uint8_t AccessMethod;
    uint8_t LogStatus;
    uint32_t LogChangeToken;
    uint32_t AccessMethodAddress;
    uint8_t LogHeaderFormat;
    uint8_t NumberOfSupportedLogTypeDescriptors;
    uint8_t LengthOfLogTypeDescriptor;
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

struct SYSTEM_LICENSE_INFORMATION {
    ULONG LicenseStatus;  // 0 = SL_GEN_STATE_IS_GENUINE
    ULONG LicenseType;    // License type
};

struct SYSTEM_POWER_CAPABILITIES
{
    BOOLEAN PowerButtonPresent;
    BOOLEAN SleepButtonPresent;
    BOOLEAN LidPresent;
    BOOLEAN SystemS1;
    BOOLEAN SystemS2;
    BOOLEAN SystemS3;
    BOOLEAN SystemS4;
    BOOLEAN SystemS5;
    BOOLEAN HiberFilePresent;
    BOOLEAN FullWake;
    BOOLEAN VideoDimPresent;
    BOOLEAN ApmPresent;
    BOOLEAN UpsPresent;
    BOOLEAN ThermalControl;
    BOOLEAN ProcessorThrottle;
    BYTE ProcessorMinThrottle;
    BYTE ProcessorMaxThrottle;
    BOOLEAN FastSystemS4;
    BYTE spare2[3];
    BOOLEAN DiskSpinDown;
    BYTE spare3[8];
    BOOLEAN SystemBatteriesPresent;
    BOOLEAN BatteriesAreShortTerm;
    struct {
        DWORD Granularity;
        DWORD Capacity;
    } BatteryScale[3];
    DWORD AcOnLineWake;
    DWORD SoftLidWake;
    DWORD RtcWake;
    DWORD MinDeviceWakeState;
    DWORD DefaultLowLatencyWake;
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
    NTSTATUS handle_SystemLicenseInformation(const syscall_context& c, const uint64_t system_information,
                                             const uint32_t system_information_length, const emulator_object<uint32_t> return_length);
    NTSTATUS handle_QueryKeyCachedInformation(const syscall_context& c, const uint64_t key_information, const ULONG length,
                                              const emulator_object<ULONG> result_length, const handle key_handle);
    NTSTATUS handle_SystemPowerCapabilities(const syscall_context& c, const uint64_t output_buffer, const ULONG output_buffer_length);
    BOOL power_capabilities();

    // Timer-related anti-debug bypass
    NTSTATUS handle_NtSetTimerEx(const syscall_context& c, handle timer_handle, uint32_t timer_set_info_class,
                                  uint64_t timer_set_information, ULONG timer_set_information_length);
}