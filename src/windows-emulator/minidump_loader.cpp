#include "std_include.hpp"
#include "minidump_loader.hpp"
#include "windows_emulator.hpp"
#include "windows_objects.hpp"
#include "emulator_thread.hpp"
#include "common/platform/unicode.hpp"
#include "common/platform/kernel_mapped.hpp"
#include "memory_utils.hpp"
#include "cpu_context.hpp"
#include <minidump/minidump.hpp>
#include "anti_debug.hpp"
#include "io_device.hpp"

namespace minidump_loader
{
    namespace
    {
        void setup_gdt(x86_64_emulator& emu, memory_manager& memory)
        {
            memory.allocate_memory(GDT_ADDR, static_cast<size_t>(page_align_up(GDT_LIMIT)), memory_permission::read);
            emu.load_gdt(GDT_ADDR, GDT_LIMIT);

            emu.write_memory<uint64_t>(GDT_ADDR + 6 * (sizeof(uint64_t)), 0xEFFE000000FFFF);
            emu.reg<uint16_t>(x86_register::cs, 0x33);

            emu.write_memory<uint64_t>(GDT_ADDR + 5 * (sizeof(uint64_t)), 0xEFF6000000FFFF);
            emu.reg<uint16_t>(x86_register::ss, 0x2B);
        }

        void setup_infrastructure(windows_emulator& win_emu)
        {
            win_emu.log.info("Setting up base infrastructure (GDT, KUSD)\n");
            setup_gdt(win_emu.emu(), win_emu.memory);
            win_emu.process.kusd.setup();
        }
    }
    struct dump_statistics
    {
        size_t thread_count = 0;
        size_t module_count = 0;
        size_t memory_region_count = 0;
        size_t memory_segment_count = 0;
        size_t handle_count = 0;
        uint64_t total_memory_size = 0;
        bool has_exception = false;
        bool has_system_info = false;
    };

    std::string get_architecture_string(const minidump::minidump_file* dump_file)
    {
        if (!dump_file)
        {
            return "Unknown";
        }

        const auto* sys_info = dump_file->get_system_info();
        if (!sys_info)
        {
            return "Unknown";
        }

        const auto arch = static_cast<minidump::processor_architecture>(sys_info->processor_architecture);
        switch (arch)
        {
        case minidump::processor_architecture::amd64:
            return "x64 (AMD64)";
        case minidump::processor_architecture::intel:
            return "x86 (Intel)";
        case minidump::processor_architecture::arm64:
            return "ARM64";
        default:
            return "Unknown (" + std::to_string(static_cast<int>(arch)) + ")";
        }
    }

    bool parse_minidump_file(windows_emulator& win_emu, const std::filesystem::path& minidump_path,
                             std::unique_ptr<minidump::minidump_file>& dump_file, std::unique_ptr<minidump::minidump_reader>& dump_reader)
    {
        win_emu.log.info("Parsing minidump file\n");

        if (!std::filesystem::exists(minidump_path))
        {
            win_emu.log.error("Minidump file does not exist: %s\n", minidump_path.string().c_str());
            return false;
        }

        const auto file_size = std::filesystem::file_size(minidump_path);
        win_emu.log.info("File size: %ju bytes\n", file_size);

        auto parsed_file = minidump::minidump_file::parse(minidump_path.string());
        if (!parsed_file)
        {
            win_emu.log.error("Failed to parse minidump file\n");
            return false;
        }

        win_emu.log.info("Minidump header parsed successfully\n");

        auto reader = parsed_file->get_reader();
        if (!reader)
        {
            win_emu.log.error("Failed to create minidump reader\n");
            return false;
        }

        dump_file = std::move(parsed_file);
        dump_reader = std::move(reader);

        win_emu.log.info("Minidump reader created successfully\n");
        return true;
    }

    bool validate_dump_compatibility(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        win_emu.log.info("Validating dump compatibility\n");

        if (!dump_file)
        {
            win_emu.log.error("Dump file not loaded\n");
            return false;
        }

        const auto& header = dump_file->header();

        if (!header.is_valid())
        {
            win_emu.log.error("Invalid minidump signature or header\n");
            return false;
        }

        win_emu.log.info("Minidump signature: 0x%08X (valid)\n", header.signature);
        win_emu.log.info("Version: %u.%u\n", header.version, header.implementation_version);
        win_emu.log.info("Number of streams: %u\n", header.number_of_streams);
        win_emu.log.info("Flags: 0x%016" PRIx64 "\n", header.flags);

        const auto* sys_info = dump_file->get_system_info();
        if (sys_info)
        {
            const auto arch = static_cast<minidump::processor_architecture>(sys_info->processor_architecture);
            const bool is_x64 = (arch == minidump::processor_architecture::amd64);

            win_emu.log.info("Processor architecture: %s\n", get_architecture_string(dump_file).c_str());

            if (!is_x64)
            {
                win_emu.log.error("Only x64 minidumps are currently supported\n");
                return false;
            }

            win_emu.log.info("Architecture compatibility: OK (x64)\n");
        }
        else
        {
            win_emu.log.warn("No system info stream found - proceeding with caution\n");
        }

        return true;
    }

    void log_dump_summary(windows_emulator& win_emu, const minidump::minidump_file* dump_file, dump_statistics& stats)
    {
        win_emu.log.info("Generating dump summary\n");

        stats = {};

        if (!dump_file)
        {
            win_emu.log.error("Dump file not loaded\n");
            return;
        }

        stats.thread_count = dump_file->threads().size();
        stats.module_count = dump_file->modules().size();
        stats.memory_region_count = dump_file->memory_regions().size();
        stats.memory_segment_count = dump_file->memory_segments().size();
        stats.handle_count = dump_file->handles().size();
        stats.has_exception = (dump_file->get_exception_info() != nullptr);
        stats.has_system_info = (dump_file->get_system_info() != nullptr);

        for (const auto& segment : dump_file->memory_segments())
        {
            stats.total_memory_size += segment.size;
        }

        win_emu.log.info("Summary: %s, %zu threads, %zu modules, %zu regions, %zu segments, %zu handles, %" PRIu64 " bytes memory\n",
                         get_architecture_string(dump_file).c_str(), stats.thread_count, stats.module_count, stats.memory_region_count,
                         stats.memory_segment_count, stats.handle_count, stats.total_memory_size);
    }

    void process_streams(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        if (!dump_file)
        {
            return;
        }

        // Process system info
        const auto* sys_info = dump_file->get_system_info();
        if (sys_info)
        {
            win_emu.log.info("System: OS %u.%u.%u, %u processors, type %u, platform %u\n", sys_info->major_version, sys_info->minor_version,
                             sys_info->build_number, sys_info->number_of_processors, sys_info->product_type, sys_info->platform_id);
        }

        // Process memory info
        const auto& memory_regions = dump_file->memory_regions();
        uint64_t total_reserved = 0;
        uint64_t total_committed = 0;
        size_t guard_pages = 0;
        for (const auto& region : memory_regions)
        {
            total_reserved += region.region_size;
            if (region.state & MEM_COMMIT)
            {
                total_committed += region.region_size;
            }
            if (region.protect & PAGE_GUARD)
            {
                guard_pages++;
            }
        }
        win_emu.log.info("Memory: %zu regions, %" PRIu64 " bytes reserved, %" PRIu64 " bytes committed, %zu guard pages\n",
                         memory_regions.size(), total_reserved, total_committed, guard_pages);

        // Process memory content
        const auto& memory_segments = dump_file->memory_segments();
        uint64_t min_addr = UINT64_MAX;
        uint64_t max_addr = 0;
        for (const auto& segment : memory_segments)
        {
            min_addr = std::min(min_addr, segment.start_virtual_address);
            max_addr = std::max(max_addr, segment.end_virtual_address());
        }
        if (!memory_segments.empty())
        {
            win_emu.log.info("Content: %zu segments, range 0x%" PRIx64 "-0x%" PRIx64 " (%" PRIu64 " bytes span)\n", memory_segments.size(),
                             min_addr, max_addr, max_addr - min_addr);
        }

        // Process modules
        const auto& modules = dump_file->modules();
        for (const auto& mod : modules)
        {
            win_emu.log.info("Module: %s at 0x%" PRIx64 " (%u bytes)\n", mod.module_name.c_str(), mod.base_of_image, mod.size_of_image);
        }

        // Process threads
        const auto& threads = dump_file->threads();
        for (const auto& thread : threads)
        {
            win_emu.log.info("Thread %u: TEB 0x%" PRIx64 ", stack 0x%" PRIx64 " (%u bytes), context %u bytes\n", thread.thread_id,
                             thread.teb, thread.stack_start_of_memory_range, thread.stack_data_size, thread.context_data_size);
        }

        // Process handles
        const auto& handles = dump_file->handles();
        if (!handles.empty())
        {
            std::map<std::string, size_t> handle_type_counts;
            for (const auto& handle : handles)
            {
                handle_type_counts[handle.type_name]++;
            }
            win_emu.log.info("Handles: %zu total\n", handles.size());
            for (const auto& [type, count] : handle_type_counts)
            {
                win_emu.log.info("  %s: %zu\n", type.c_str(), count);
            }
        }

        // Process exception info
        const auto* exception = dump_file->get_exception_info();
        if (exception)
        {
            win_emu.log.info("Exception: thread %u, code 0x%08X at 0x%" PRIx64 "\n", exception->thread_id,
                             exception->exception_record.exception_code, exception->exception_record.exception_address);
        }
    }

    void reconstruct_memory_state(windows_emulator& win_emu, const minidump::minidump_file* dump_file,
                                  minidump::minidump_reader* dump_reader)
    {
        if (!dump_file || !dump_reader)
        {
            win_emu.log.error("Dump file or reader not loaded\n");
            return;
        }

        const auto& memory_regions = dump_file->memory_regions();
        const auto& memory_segments = dump_file->memory_segments();

        win_emu.log.info("Reconstructing memory: %zu regions, %zu data segments\n", memory_regions.size(), memory_segments.size());
        size_t reserved_count = 0;
        size_t committed_count = 0;
        size_t failed_count = 0;

        for (const auto& region : memory_regions)
        {
            // Log the memory region details
            win_emu.log.info("Region: 0x%" PRIx64 ", size=%" PRIu64 ", state=0x%08X, protect=0x%08X\n", region.base_address,
                             region.region_size, region.state, region.protect);

            const bool is_reserved = (region.state & MEM_RESERVE) != 0;
            const bool is_committed = (region.state & MEM_COMMIT) != 0;
            const bool is_free = (region.state & MEM_FREE) != 0;

            if (is_free)
            {
                continue;
            }

            auto protect_value = region.protect;
            if (protect_value == 0)
            {
                protect_value = PAGE_READONLY;
                win_emu.log.warn("  Region 0x%" PRIx64 " has zero protection, using PAGE_READONLY\n", region.base_address);
            }

            memory_permission perms = map_nt_to_emulator_protection(protect_value);

            try
            {
                if (is_committed)
                {
                    if (win_emu.memory.allocate_memory(region.base_address, static_cast<size_t>(region.region_size), perms, false))
                    {
                        committed_count++;
                        win_emu.log.info("  Allocated committed 0x%" PRIx64 ": size=%" PRIu64 ", state=0x%08X, protect=0x%08X\n",
                                         region.base_address, region.region_size, region.state, region.protect);
                    }
                    else
                    {
                        failed_count++;
                        win_emu.log.warn("  Failed to allocate committed 0x%" PRIx64 ": size=%" PRIu64 "\n", region.base_address,
                                         region.region_size);
                    }
                }
                else if (is_reserved)
                {
                    if (win_emu.memory.allocate_memory(region.base_address, static_cast<size_t>(region.region_size), perms, true))
                    {
                        reserved_count++;
                        win_emu.log.info("  Reserved 0x%" PRIx64 ": size=%" PRIu64 ", state=0x%08X, protect=0x%08X\n", region.base_address,
                                         region.region_size, region.state, region.protect);
                    }
                    else
                    {
                        failed_count++;
                        win_emu.log.warn("  Failed to reserve 0x%" PRIx64 ": size=%" PRIu64 "\n", region.base_address, region.region_size);
                    }
                }
            }
            catch (const std::exception& e)
            {
                failed_count++;
                win_emu.log.error("  Exception allocating 0x%" PRIx64 ": %s\n", region.base_address, e.what());
            }
        }

        win_emu.log.info("Regions: %zu reserved, %zu committed, %zu failed\n", reserved_count, committed_count, failed_count);
        size_t written_count = 0;
        size_t write_failed_count = 0;
        uint64_t total_bytes_written = 0;

        for (const auto& segment : memory_segments)
        {
            try
            {
                auto memory_data = dump_reader->read_memory(segment.start_virtual_address, static_cast<size_t>(segment.size));
                win_emu.memory.write_memory(segment.start_virtual_address, memory_data.data(), static_cast<size_t>(memory_data.size()));
                written_count++;
                total_bytes_written += memory_data.size();
                win_emu.log.info("  Written segment 0x%" PRIx64 ": %zu bytes\n", segment.start_virtual_address, memory_data.size());
            }
            catch (const std::exception& e)
            {
                write_failed_count++;
                win_emu.log.error("  Failed to write segment 0x%" PRIx64 ": %s\n", segment.start_virtual_address, e.what());
            }
        }

        win_emu.log.info("Content: %zu segments written (%" PRIu64 " bytes), %zu failed\n", written_count, total_bytes_written,
                         write_failed_count);
    }

    bool is_main_executable(const minidump::module_info& mod)
    {
        const auto name = mod.module_name;
        return name.find(".exe") != std::string::npos;
    }

    bool ends_with_insensitive(const std::string& str, const std::string& suffix)
    {
        if (str.length() < suffix.length())
        {
            return false;
        }
        return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin(), [](char a, char b) {
            return std::tolower(a) == std::tolower(b);
        });
    }

    bool is_ntdll(const minidump::module_info& mod)
    {
        return ends_with_insensitive(mod.module_name, "ntdll.dll");
    }

    bool is_win32u(const minidump::module_info& mod)
    {
        return ends_with_insensitive(mod.module_name, "win32u.dll");
    }

    void reconstruct_module_state(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        if (!dump_file)
        {
            win_emu.log.error("Dump file not loaded\n");
            return;
        }

        const auto& modules = dump_file->modules();
        win_emu.log.info("Reconstructing module state: %zu modules\n", modules.size());

        size_t mapped_count = 0;
        size_t failed_count = 0;
        size_t identified_count = 0;

        for (const auto& mod : modules)
        {
            try
            {
                auto* mapped_module =
                    win_emu.mod_manager.map_memory_module(mod.base_of_image, mod.size_of_image, mod.module_name, win_emu.log);

                if (mapped_module)
                {
                    mapped_count++;
                    win_emu.log.info("  Mapped %s at 0x%" PRIx64 " (%u bytes, %zu sections, %zu exports)\n", mod.module_name.c_str(),
                                     mod.base_of_image, mod.size_of_image, mapped_module->sections.size(), mapped_module->exports.size());

                    if (is_main_executable(mod))
                    {
                        win_emu.mod_manager.executable = mapped_module;
                        identified_count++;
                        win_emu.log.info("    Identified as main executable\n");
                    }
                    else if (is_ntdll(mod))
                    {
                        win_emu.mod_manager.ntdll = mapped_module;
                        identified_count++;
                        win_emu.log.info("    Identified as ntdll\n");

                        auto& process = win_emu.process;
                        process.ntdll_image_base = mapped_module->image_base;
                        process.ldr_initialize_thunk = mapped_module->find_export("LdrInitializeThunk");
                        process.rtl_user_thread_start = mapped_module->find_export("RtlUserThreadStart");
                        process.ki_user_apc_dispatcher = mapped_module->find_export("KiUserApcDispatcher");
                        process.ki_user_exception_dispatcher = mapped_module->find_export("KiUserExceptionDispatcher");
                        win_emu.log.info("    ntdll function pointers resolved\n");
                    }
                    else if (is_win32u(mod))
                    {
                        win_emu.mod_manager.win32u = mapped_module;
                        identified_count++;
                        win_emu.log.info("    Identified as win32u\n");
                    }
                }
                else
                {
                    failed_count++;
                    win_emu.log.warn("  Failed to map %s at 0x%" PRIx64 "\n", mod.module_name.c_str(), mod.base_of_image);
                }
            }
            catch (const std::exception& e)
            {
                failed_count++;
                win_emu.log.error("  Exception mapping %s: %s\n", mod.module_name.c_str(), e.what());
            }
        }

        win_emu.log.info("Module reconstruction: %zu mapped, %zu failed, %zu system modules identified\n", mapped_count, failed_count,
                         identified_count);
    }

    void setup_kusd_from_dump(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        const auto* sys_info = dump_file->get_system_info();
        if (!sys_info)
        {
            win_emu.log.warn("No system info available - using default KUSD\n");
            return;
        }

        win_emu.log.info("Setting up KUSER_SHARED_DATA from dump system info\n");

        auto& kusd = win_emu.process.kusd.get();
        kusd.NtMajorVersion = sys_info->major_version;
        kusd.NtMinorVersion = sys_info->minor_version;
        kusd.NtBuildNumber = sys_info->build_number;
        kusd.NativeProcessorArchitecture = sys_info->processor_architecture;
        kusd.ActiveProcessorCount = sys_info->number_of_processors;
        kusd.UnparkedProcessorCount = sys_info->number_of_processors;
        kusd.NtProductType = static_cast<NT_PRODUCT_TYPE>(sys_info->product_type);
        kusd.ProductTypeIsValid = 1;

        win_emu.log.info("KUSD updated: Windows %u.%u.%u, %u processors, product type %u\n", sys_info->major_version,
                         sys_info->minor_version, sys_info->build_number, sys_info->number_of_processors, sys_info->product_type);
    }

    bool load_thread_context(const std::filesystem::path& minidump_path, const minidump::thread_info& thread_info,
                             std::vector<std::byte>& context_buffer)
    {
        if (thread_info.context_data_size == 0)
        {
            return false;
        }

        std::ifstream context_file(minidump_path, std::ios::binary);
        if (!context_file.is_open())
        {
            return false;
        }

        context_file.seekg(thread_info.context_rva);
        context_buffer.resize(thread_info.context_data_size);
        context_file.read(reinterpret_cast<char*>(context_buffer.data()), thread_info.context_data_size);

        return context_file.good();
    }

    void reconstruct_threads(windows_emulator& win_emu, const minidump::minidump_file* dump_file,
                             const std::filesystem::path& minidump_path)
    {
        const auto& threads = dump_file->threads();
        if (threads.empty())
        {
            win_emu.log.warn("No threads found in minidump\n");
            return;
        }

        win_emu.log.info("Reconstructing threads: %zu threads\n", threads.size());

        size_t success_count = 0;
        size_t context_loaded_count = 0;

        const auto* exception_info = dump_file->get_exception_info();
        const uint32_t exception_thread_id = exception_info ? exception_info->thread_id : threads[0].thread_id;
        emulator_thread* active_thread = nullptr;

        for (const auto& thread_info : threads)
        {
            try
            {
                emulator_thread thread(win_emu.memory);
                thread.id = thread_info.thread_id;
                thread.stack_base = thread_info.stack_start_of_memory_range;
                thread.stack_size = thread_info.stack_data_size;
                thread.suspended = thread_info.suspend_count;

                // Set TEB address if valid
                if (thread_info.teb != 0)
                {
                    thread.teb.emplace(win_emu.memory);
                    thread.teb->set_address(thread_info.teb);

                    // Reconstruct TEB stack limits
                    auto teb_writable = thread.teb->read(); // Create a mutable copy
                    teb_writable.NtTib.StackBase = thread_info.stack_start_of_memory_range + thread_info.stack_data_size;

                    // Try to read the original StackLimit directly from the TEB memory in the dump
                    uint64_t original_stack_limit_from_teb = 0;
                    try
                    {
                        win_emu.memory.read_memory(thread_info.teb + offsetof(TEB64, NtTib) + offsetof(NT_TIB64, StackLimit),
                                                   &original_stack_limit_from_teb, sizeof(original_stack_limit_from_teb));
                    }
                    catch (const std::exception&)
                    {
                        // Ignore if we can't read it, we'll fall back.
                        original_stack_limit_from_teb = 0;
                    }

                    // The minidump info stream gives us the limit of the committed part of the stack.
                    const uint64_t stack_limit_from_info = thread_info.stack_start_of_memory_range;
                    
                    // The real stack limit is the lowest of these two values (if the TEB one is valid).
                    uint64_t final_stack_limit = stack_limit_from_info;
                    if (original_stack_limit_from_teb != 0 && original_stack_limit_from_teb < final_stack_limit)
                    {
                        final_stack_limit = original_stack_limit_from_teb;
                    }

                    const uint64_t stack_allocation_base = final_stack_limit;
                    const size_t stack_size = teb_writable.NtTib.StackBase - stack_allocation_base;

                    // Reserve the entire stack region.
                    if (stack_size > 0)
                    {
                        win_emu.memory.allocate_memory(stack_allocation_base, stack_size, memory_permission::read | memory_permission::write, true);
                        win_emu.log.info("  Dynamically reserved stack for TID %u at 0x%" PRIx64 " (Size: %zu KB)\n",
                                         thread_info.thread_id, stack_allocation_base, stack_size / 1024);
                    }
                    
                    // Set the final, correct stack limit in our TEB copy.
                    teb_writable.NtTib.StackLimit = final_stack_limit;
                    
                    thread.teb->write(teb_writable);
                }

                // Load CPU context if available
                const bool context_loaded = load_thread_context(minidump_path, thread_info, thread.last_registers);
                if (context_loaded)
                {
                    context_loaded_count++;
                }

                win_emu.log.info("  Thread %u: TEB=0x%" PRIx64 ", stack=0x%" PRIx64 " (%u bytes), context=%s\n", thread_info.thread_id,
                                 thread_info.teb, thread.stack_base, thread_info.stack_data_size,
                                 context_loaded ? "loaded" : "unavailable");

                auto [h, thr] = win_emu.process.threads.store_and_get(std::move(thread));
                success_count++;

                if (thr->id == exception_thread_id)
                {
                    active_thread = thr;
                }
            }
            catch (const std::exception& e)
            {
                win_emu.log.error("  Failed to reconstruct thread %u: %s\n", thread_info.thread_id, e.what());
            }
        }

        // Set active thread to the one that caused the exception
        if (active_thread)
        {
            win_emu.log.info("Setting active thread to %u (exception thread)\n", active_thread->id);
            win_emu.process.active_thread = active_thread;

            if (!active_thread->last_registers.empty())
            {
                const auto* context = reinterpret_cast<const CONTEXT64*>(active_thread->last_registers.data());
                // Dynamically patch the GDT to make the minidump's GS selector valid.
                // This avoids a hardware exception when restoring the context.
                const uint16_t gs_selector = context->SegGs;
                if (gs_selector != 0)
                {
                    const uint16_t gdt_index = gs_selector >> 3;
                    win_emu.log.info("  Patching GDT index %u for GS selector 0x%X\n", gdt_index, gs_selector);

                    // We use the descriptor we already created for FS/GS at index 4 (selector 0x23)
                    // as a known-good descriptor.
                    const uint64_t valid_descriptor = win_emu.emu().read_memory<uint64_t>(GDT_ADDR + 4 * sizeof(uint64_t));
                    win_emu.emu().write_memory<uint64_t>(GDT_ADDR + gdt_index * sizeof(uint64_t), valid_descriptor);
                }

                cpu_context::restore(win_emu.emu(), *context);

                // If the trap flag is set in the minidump's context, clear it.
                // This prevents the emulator from immediately breaking on a single-step exception
                // which is often not the desired behavior when analyzing a crash dump.
                const auto eflags = win_emu.emu().reg<uint32_t>(x86_register::eflags);
                if (eflags & 0x100)
                {
                    win_emu.log.info("  Clearing trap flag set in minidump context (EFlags=0x%X)\n", eflags);
                    win_emu.emu().reg<uint32_t>(x86_register::eflags, eflags & ~0x100);
                }

                win_emu.log.info("  Restored CPU context from minidump. RIP=0x%" PRIx64 ", RSP=0x%" PRIx64 "\n", context->Rip,
                                 context->Rsp);

                // This is the critical part: Set the GS base to the TEB address for the active thread
                if (active_thread->teb && active_thread->teb->value() != 0)
                {
                    win_emu.emu().set_segment_base(x86_register::gs_base, active_thread->teb->value());
                    win_emu.log.info("  Set GS base to TEB: 0x%" PRIx64 "\n", active_thread->teb->value());
                }
            }
        }
        else if (success_count > 0)
        {
            auto& first_thread = win_emu.process.threads.begin()->second;
            win_emu.process.active_thread = &first_thread;
            win_emu.log.warn("Exception thread not found, setting active thread to %u\n", first_thread.id);
        }

        win_emu.log.info("Thread reconstruction: %zu/%zu threads created, %zu with context\n", success_count, threads.size(),
                         context_loaded_count);
    }
    
    void setup_peb_from_teb(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        const auto& threads = dump_file->threads();
        if (threads.empty())
        {
            win_emu.log.warn("No threads available for PEB setup\n");
            return;
        }

        const auto& first_thread = threads[0];
        if (first_thread.teb == 0)
        {
            win_emu.log.warn("Thread %u has null TEB address\n", first_thread.thread_id);
            return;
        }

        try
        {
            constexpr uint64_t teb_peb_offset = offsetof(TEB64, ProcessEnvironmentBlock);
            uint64_t peb_address = 0;

            win_emu.memory.read_memory(first_thread.teb + teb_peb_offset, &peb_address, sizeof(peb_address));

            if (peb_address == 0)
            {
                win_emu.log.warn("PEB address is null in TEB at 0x%" PRIx64 "\n", first_thread.teb);
                return;
            }

            win_emu.process.peb.set_address(peb_address);
            win_emu.log.info("PEB address: 0x%" PRIx64 " (from TEB 0x%" PRIx64 ")\n", peb_address, first_thread.teb);

            // PEB'deki BeingDebugged bayrağını kontrol et ve sıfırla (anti-debug)
            try
            {
                constexpr uint64_t peb_being_debugged_offset = offsetof(PEB64, BeingDebugged);
                uint8_t being_debugged = 0;
                win_emu.memory.read_memory(peb_address + peb_being_debugged_offset, &being_debugged, sizeof(being_debugged));

                if (being_debugged != 0)
                {
                    win_emu.log.info("PEB BeingDebugged flag detected (0x%02X), clearing for anti-debug bypass\n", being_debugged);
                    being_debugged = 0;
                    win_emu.memory.write_memory(peb_address + peb_being_debugged_offset, &being_debugged, sizeof(being_debugged));
                    win_emu.log.info("PEB BeingDebugged flag cleared successfully\n");
                }
                else
                {
                    win_emu.log.info("PEB BeingDebugged flag is already cleared\n");
                }
            }
            catch (const std::exception& e)
            {
                win_emu.log.warn("Failed to access PEB BeingDebugged flag: %s\n", e.what());
            }
        }
        catch (const std::exception& e)
        {
            win_emu.log.error("Failed to read PEB from TEB: %s\n", e.what());
        }
    }

    void reconstruct_handle_table(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        const auto& handles = dump_file->handles();
        if (handles.empty())
        {
            return;
        }

        win_emu.log.info("Reconstructing handle table: %zu handles\n", handles.size());

        std::map<std::string, size_t> handle_type_counts;
        size_t created_count = 0;

        for (const auto& handle_info : handles)
        {
            handle_type_counts[handle_info.type_name]++;

            // Debug: Log all handle IDs
            if (handle_info.object_name.find("\\Device\\ConDrv") == 0)
            {
                win_emu.log.info("  Minidump ConDrv handle: ID=0x%" PRIx64 ", name='%s'\n",
                                handle_info.handle, handle_info.object_name.c_str());
            }

            handle created_handle{};

            try
            {
                if (handle_info.type_name == "Event")
                {
                    event evt{};
                    evt.name = u8_to_u16(handle_info.object_name);

                    // Check for EmuHandleStream data to set initial signaled state
                    const auto& emu_handles = dump_file->emu_handle_entries();
                    for (const auto& emu_handle : emu_handles)
                    {
                        if (emu_handle.handle_value == handle_info.handle &&
                            emu_handle.emu_type == minidump::emu_handle_type::event)
                        {
                            // Found matching EmuHandle entry
                            if ((emu_handle.flags & minidump::EMU_HANDLE_FLAG_HAS_STATE_INFO) != 0 &&
                                emu_handle.detail_rva != 0 && emu_handle.detail_size > 0)
                            {
                                try
                                {
                                    const minidump::emu_event_info_v1* event_info =
                                        reinterpret_cast<const minidump::emu_event_info_v1*>(
                                            dump_file->emu_handle_detail_data().data() + emu_handle.detail_rva);

                                    if (event_info->signaled != 0xFF) // Not unknown
                                    {
                                        evt.signaled = (event_info->signaled == 1);
                                        evt.type = (event_info->manual_reset == 1) ?
                                            SynchronizationEvent : NotificationEvent;
                                        win_emu.log.info("  Set initial signaled state for Event handle 0x%" PRIx64 ": signaled=%s, type=%s\n",
                                                        handle_info.handle, evt.signaled ? "true" : "false",
                                                        evt.type == SynchronizationEvent ? "SynchronizationEvent" : "NotificationEvent");
                                    }
                                }
                                catch (const std::exception& e)
                                {
                                    win_emu.log.warn("  Failed to read EmuHandle event info for handle 0x%" PRIx64 ": %s\n",
                                                    handle_info.handle, e.what());
                                }
                            }
                            break; // Found the matching handle
                        }
                    }

                    created_handle = win_emu.process.events.store(std::move(evt));
                    created_count++;
                }
                else if (handle_info.type_name == "File")
                {
                    // Check if this is a device file (like \Device\ConDrv)
                    const std::u16string obj_name = u8_to_u16(handle_info.object_name);
                    const auto device_prefix = std::u16string_view(u"\\Device\\");
                    if (obj_name.starts_with(device_prefix))
                    {
                        // Special handling for ConDrv console handles
                        if (obj_name == u"\\Device\\ConDrv")
                        {
                            // Map ConDrv handles by their raw handle ID to standard console handles
                            // Raw handle 0x48 -> CONSOLE_HANDLE, 0x50 -> STDIN_HANDLE, 0x58 -> STDOUT_HANDLE
                            handle mapped_handle{};
                            if (handle_info.handle == 0x48)
                            {
                                mapped_handle = CONSOLE_HANDLE;
                            }
                            else if (handle_info.handle == 0x54)
                            {
                                mapped_handle = STDIN_HANDLE;
                            }
                            else if (handle_info.handle == 0x58)
                            {
                                mapped_handle = STDOUT_HANDLE;
                            }
                            else
                            {
                                // Create device for other ConDrv handles
                                io_device_creation_data data{};
                                io_device_container container{u"ConDrv", win_emu, data};
                                if (!container)
                                {
                                    win_emu.log.error("  Failed to create ConDrv device for %s\n", handle_info.object_name.c_str());
                                    continue;
                                }
                                created_handle = win_emu.process.devices.store(std::move(container));
                                created_count++;
                            }

                            if (mapped_handle.bits != 0)
                            {
                                // Use the pre-defined pseudo handle instead of creating a new one
                                win_emu.process.minidump_handle_mapping[handle_info.handle] = mapped_handle;
                                win_emu.log.info("  Mapped ConDrv handle 0x%" PRIx64 " -> standard console handle 0x%" PRIx64 "\n",
                                                handle_info.handle, mapped_handle.bits);
                                continue; // Skip the normal mapping below
                            }
                        }
                        else
                        {
                            // Create device for other device types
                            const auto device_name = obj_name.substr(device_prefix.size());
                            io_device_creation_data data{};
                            io_device_container container{std::u16string(device_name), win_emu, data};
                            if (!container)
                            {
                                win_emu.log.error("  Failed to create device for %s\n", handle_info.object_name.c_str());
                                continue;
                            }
                            created_handle = win_emu.process.devices.store(std::move(container));
                            created_count++;
                        }
                    }
                    else
                    {
                        file f{};
                        f.name = obj_name;
                        created_handle = win_emu.process.files.store(std::move(f));
                        created_count++;
                    }
                }
                else if (handle_info.type_name == "Mutant")
                {
                    mutant m{};
                    m.name = u8_to_u16(handle_info.object_name);
                    created_handle = win_emu.process.mutants.store(std::move(m));
                    created_count++;
                }
                else if (handle_info.type_name == "Directory")
                {
                    const std::u16string name = u8_to_u16(handle_info.object_name);
                    
                    if (name == u"\\KnownDlls")
                    {
                        created_handle = KNOWN_DLLS_DIRECTORY;
                        win_emu.log.info("  Identified KnownDlls directory handle: 0x%" PRIx64 "\n", handle_info.handle);
                    }
                    else if (name == u"\\BaseNamedObjects") // Or similar common directories
                    {
                        created_handle = BASE_NAMED_OBJECTS_DIRECTORY;
                        win_emu.log.info("  Identified BaseNamedObjects directory handle: 0x%" PRIx64 "\n", handle_info.handle);
                    }
                    else if (name == u"\\RPC Control")
                    {
                        created_handle = RPC_CONTROL_DIRECTORY;
                        win_emu.log.info("  Identified RPC Control directory handle: 0x%" PRIx64 "\n", handle_info.handle);
                    }
                    else
                    {
                        // We can't store generic directories yet as there is no directory store in process_context
                        win_emu.log.warn("  Skipping generic directory handle: %s (0x%" PRIx64 ")\n", handle_info.object_name.c_str(), handle_info.handle);
                    }

                    if (created_handle.bits != 0)
                    {
                        // If it's a pseudo handle (like KNOWN_DLLS_DIRECTORY), we don't count it as 'created' in the store sense,
                        // but we definitely need to map it.
                        win_emu.process.minidump_handle_mapping[handle_info.handle] = created_handle;
                        win_emu.log.info("  Mapped directory handle 0x%" PRIx64 " -> emulator handle 0x%" PRIx64 "\n",
                                        handle_info.handle, created_handle.bits);
                        
                        // Only increment if we actually stored something new, but pseudo handles are fine too for stats
                        created_count++;
                    }
                    continue; // Skip the default mapping logic below as we handled it here
                }
                // Map the minidump raw handle to the emulator encoded handle
                if (created_handle.bits != 0)
                {
                    win_emu.process.minidump_handle_mapping[handle_info.handle] = created_handle;
                    win_emu.log.info("  Mapped minidump handle 0x%" PRIx64 " -> emulator handle 0x%" PRIx64 "\n",
                                    handle_info.handle, created_handle.bits);
                }
            }
            catch (const std::exception& e)
            {
                win_emu.log.error("  Failed to create %s handle '%s': %s\n", handle_info.type_name.c_str(), handle_info.object_name.c_str(),
                                  e.what());
            }
        }

        // Log summary by type
        for (const auto& [type, count] : handle_type_counts)
        {
            win_emu.log.info("  %s: %zu handles\n", type.c_str(), count);
        }

        win_emu.log.info("Handle table: %zu/%zu handles reconstructed\n", created_count, handles.size());
    }

    void setup_exception_context(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        const auto* exception_info = dump_file->get_exception_info();
        if (!exception_info)
        {
            return;
        }

        win_emu.log.info("Exception context: address=0x%" PRIx64 ", code=0x%08X, thread=%u\n",
                         exception_info->exception_record.exception_address, exception_info->exception_record.exception_code,
                         exception_info->thread_id);
    }

    void load_minidump_into_emulator(windows_emulator& win_emu, const std::filesystem::path& minidump_path)
    {
        win_emu.log.info("Starting minidump loading process\n");
        win_emu.log.info("Minidump file: %s\n", minidump_path.string().c_str());

        try
        {
            std::unique_ptr<minidump::minidump_file> dump_file;
            std::unique_ptr<minidump::minidump_reader> dump_reader;

            if (!parse_minidump_file(win_emu, minidump_path, dump_file, dump_reader))
            {
                throw std::runtime_error("Failed to parse minidump file");
            }

            if (!validate_dump_compatibility(win_emu, dump_file.get()))
            {
                throw std::runtime_error("Minidump compatibility validation failed");
            }

            // 1. Setup minimal OS infrastructure that is not part of the dump
            setup_infrastructure(win_emu);
            setup_kusd_from_dump(win_emu, dump_file.get());

            dump_statistics stats;
            log_dump_summary(win_emu, dump_file.get(), stats);
            process_streams(win_emu, dump_file.get());

            // 2. Reconstruct the memory map and content from the dump
            reconstruct_memory_state(win_emu, dump_file.get(), dump_reader.get());

            // Synchronize the C++ KUSD object with the memory restored from the minidump
            win_emu.log.info("Synchronizing KUSD object from emulated memory...\n");
            win_emu.memory.read_memory(kusd_mmio::address(), &win_emu.process.kusd.get(), sizeof(KUSER_SHARED_DATA64));

            // 3. Reconstruct modules from memory and resolve critical ntdll functions
            reconstruct_module_state(win_emu, dump_file.get());

            // 4. Setup syscall dispatcher now that modules are loaded
            win_emu.log.info("Setting up syscall dispatcher...\n");
            const auto* ntdll = win_emu.mod_manager.ntdll;
            const auto* win32u = win_emu.mod_manager.win32u;

            if (ntdll)
            {
                const auto ntdll_data = win_emu.emu().read_memory(ntdll->image_base, static_cast<size_t>(ntdll->size_of_image));
                const auto win32u_data = win_emu.emu().read_memory(win32u->image_base, static_cast<size_t>(win32u->size_of_image));


                win_emu.dispatcher.setup(ntdll->exports, ntdll_data, win32u->exports, win32u_data);
                win_emu.log.info("Syscall dispatcher setup complete.\n");
            }
            else
            {
                win_emu.log.error("ntdll module not found, syscall dispatcher cannot be set up.\n");
            }

            // 5. Reconstruct the rest of the process state
            setup_peb_from_teb(win_emu, dump_file.get());
            reconstruct_threads(win_emu, dump_file.get(), minidump_path); // This will also set the active thread and its context
            reconstruct_handle_table(win_emu, dump_file.get());
            setup_exception_context(win_emu, dump_file.get());

            win_emu.log.info("Process state reconstruction completed\n");
        }
        catch (const std::exception& e)
        {
            win_emu.log.error("Minidump loading failed: %s\n", e.what());
            throw;
        }
    }
} // namespace minidump_loader
