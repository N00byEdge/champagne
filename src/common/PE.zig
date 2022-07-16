const std = @import("std");

const log = @import("log.zig").scoped(.PE);

const IMAGE_DIRECTORY_ENTRY_EXPORT = 0; // Export directory
const IMAGE_DIRECTORY_ENTRY_IMPORT = 1; // Import directory
const IMAGE_DIRECTORY_ENTRY_RESOURCE = 2; // Resource directory
const IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3; // Exception directory
const IMAGE_DIRECTORY_ENTRY_SECURITY = 4; // Security directory
const IMAGE_DIRECTORY_ENTRY_BASERELOC = 5; // Base relocation table
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6; // Debug directory
const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7; // Architecture-specific data
const IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8; // The relative virtual address of global pointer
const IMAGE_DIRECTORY_ENTRY_TLS = 9; // Thread local storage directory
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10; // Load configuration directory
const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11; // Bound import directory
const IMAGE_DIRECTORY_ENTRY_IAT = 12; // Import address table
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13; // Delay import table
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14; // COM descriptor table

pub fn load(file: std.fs.File, allocator: std.mem.Allocator, import_resolve_context: anytype) !usize {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var coff_file = std.coff.Coff.init(arena.allocator(), file);
    try coff_file.loadHeader();
    try coff_file.loadSections();

    var min_addr: usize = std.math.maxInt(usize);
    var max_addr: usize = std.math.minInt(usize);

    for (coff_file.sections.items) |s| {
        const header = s.header;

        if (header.virtual_address < min_addr) {
            min_addr = header.virtual_address;
        }

        const top_addr = header.virtual_address + header.misc.virtual_size;

        if (max_addr < top_addr) {
            max_addr = top_addr;
        }

        if (header.number_of_relocations != 0) {
            @panic("Section header relocations!");
        }
        log("Name: '{s}', vaddr = 0x{X}, size = 0x{}", .{ header.name[0..std.mem.indexOfScalar(u8, &header.name, 0).?], header.virtual_address, header.misc.virtual_size });
    }

    const virt_size = ((max_addr - min_addr) + 0xFFF) & ~@as(usize, 0xFFF);
    const vmem = try std.os.mmap(
        @intToPtr([*]align(4096) u8, min_addr + coff_file.pe_header.image_base),
        virt_size,
        std.os.PROT.NONE,
        std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE,
        0,
        0,
    );
    errdefer std.os.munmap(vmem);

    const load_delta = @ptrToInt(vmem.ptr) -% (min_addr + coff_file.pe_header.image_base);
    log("Allocated executable space at 0x{X} (delta 0x{X})", .{ @ptrToInt(vmem.ptr), load_delta });

    for (coff_file.sections.items) |s| {
        const header = s.header;

        const section_mem = blk: {
            var result = vmem[header.virtual_address - min_addr ..][0..header.misc.virtual_size];
            result.len += 0xFFF;
            result.len &= ~@as(usize, 0xFFF);
            break :blk result;
        };

        try std.os.mprotect(section_mem, std.os.PROT.READ | std.os.PROT.WRITE);

        //if(header.characteristics & 0x00000040 != 0) { // Section contains initialized data
        const read = try file.preadAll(
            section_mem[0..header.size_of_raw_data],
            header.pointer_to_raw_data,
        );
        if (read != header.size_of_raw_data) {
            log("Read 0x{X} but expected to read 0x{X}", .{ read, header.size_of_raw_data });
            return error.EndOfFile;
        }
        //}
        //if(header.characteristics & 0x00000080 != 0) { // Section contains uninitialized data
        std.mem.set(u8, section_mem[header.size_of_raw_data..], 0);
        //}
    }

    log("File loaded", .{});

    if (@ptrToInt(vmem.ptr) != min_addr) {
        log("File was loaded at an offset, doing relocations", .{});

        const relocs_entry = coff_file.pe_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        var reloc_block_bytes = vmem[relocs_entry.virtual_address - min_addr ..][0..relocs_entry.size];

        while (reloc_block_bytes.len >= 8) {
            const current_block_base_addr = @as(usize, std.mem.readIntNative(u32, reloc_block_bytes[0..4]));
            const num_block_bytes = std.mem.readIntNative(u32, reloc_block_bytes[4..8]);

            for (std.mem.bytesAsSlice(u16, reloc_block_bytes[8..num_block_bytes])) |reloc| {
                const block_offset = @as(usize, @truncate(u12, reloc));
                const reloc_type = @truncate(u4, reloc >> 12);

                const reloc_addr = current_block_base_addr + block_offset;
                const reloc_bytes = vmem[reloc_addr - min_addr ..];
                _ = reloc_bytes;

                //log.debug("Relocation of type {d} at addr 0x{X} (offset 0x{X})", .{reloc_type, reloc_addr, block_offset});

                switch (reloc_type) {
                    // IMAGE_REL_BASED_ABSOLUTE
                    //     The base relocation is skipped. This type can be used to pad a block.
                    0 => {},

                    // IMAGE_REL_BASED_HIGH
                    // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
                    // The 16-bit field represents the high value of a 32-bit word.
                    // 1 => std.mem.bytesAsSlice(u16, reloc_bytes)[0] +%= @truncate(u16, load_delta >> 16),

                    // IMAGE_REL_BASED_LOW
                    // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset.
                    // The 16-bit field represents the low half of a 32-bit word.
                    // 2 => std.mem.bytesAsSlice(u16, reloc_bytes)[0] +%= @truncate(u16, load_delta),

                    // IMAGE_REL_BASED_HIGHLOW
                    // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
                    // 3 => std.mem.bytesAsSlice(u32, reloc_bytes)[0] +%= @intCast(u32, load_delta),

                    // IMAGE_REL_BASED_HIGHADJ
                    // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
                    // The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit
                    // value are stored in the 16-bit word that follows this base relocation.
                    // This means that this base relocation occupies two slots.
                    // 4 => ,

                    // IMAGE_REL_BASED_MIPS_JMPADDR
                    // The relocation interpretation is dependent on the machine type.
                    // When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
                    // 5 => ,

                    // IMAGE_REL_BASED_ARM_MOV32
                    // This relocation is meaningful only when the machine type is ARM or Thumb.
                    // The base relocation applies the 32-bit address of a symbol across a consecutive
                    // MOVW/MOVT instruction pair.
                    // 5 => ,

                    // IMAGE_REL_BASED_RISCV_HIGH20
                    // This relocation is only meaningful when the machine type is RISC-V.
                    // The base relocation applies to the high 20 bits of a 32-bit absolute address.
                    // 5 => ,

                    // Reserved, must be zero.
                    // 6 => ,

                    // IMAGE_REL_BASED_THUMB_MOV32
                    // This relocation is meaningful only when the machine type is Thumb.
                    // The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT
                    // instruction pair.
                    // 7 => ,

                    // IMAGE_REL_BASED_RISCV_LOW12I
                    // This relocation is only meaningful when the machine type is RISC-V.
                    // The base relocation applies to the low 12 bits of a 32-bit absolute address formed
                    // in RISC-V I-type instruction format.
                    // 7 => ,

                    // IMAGE_REL_BASED_RISCV_LOW12S
                    // This relocation is only meaningful when the machine type is RISC-V.
                    // The base relocation applies to the low 12 bits of a 32-bit absolute address formed
                    // in RISC-V S-type instruction format.
                    // 8 => ,

                    // IMAGE_REL_BASED_LOONGARCH32_MARK_LA
                    // This relocation is only meaningful when the machine type is LoongArch 32-bit.
                    // The base relocation applies to a 32-bit absolute address formed in two consecutive instructions.
                    // 8 => ,

                    // IMAGE_REL_BASED_LOONGARCH64_MARK_LA
                    // This relocation is only meaningful when the machine type is LoongArch 64-bit.
                    // The base relocation applies to a 64-bit absolute address formed in four consecutive instructions.
                    // 8 => ,

                    // IMAGE_REL_BASED_MIPS_JMPADDR16
                    // The relocation is only meaningful when the machine type is MIPS.
                    // The base relocation applies to a MIPS16 jump instruction.
                    // 9 => ,

                    // IMAGE_REL_BASED_DIR64
                    // The base relocation applies the difference to the 64-bit field at offset.
                    10 => std.mem.bytesAsSlice(u64, reloc_bytes)[0] +%= load_delta,

                    else => {
                        log("Relocation of type {d} at addr 0x{X} (offset 0x{X})", .{ reloc_type, reloc_addr, block_offset });
                        @panic("Unknown relocation!");
                    },
                }
            }

            reloc_block_bytes = reloc_block_bytes[num_block_bytes..];
        }

        log("Relocations done", .{});
    }

    // Imports?
    blk: {
        const imports_entry = coff_file.pe_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imports_entry.size == 0)
            break :blk;
        const import_descriptor_bytes = vmem[imports_entry.virtual_address - min_addr ..][0..imports_entry.size];
        for (std.mem.bytesAsSlice(extern struct {
            import_name_table: u32,
            time_stamp: u32,
            forwarder_chain: u32,
            dll_name_addr: u32,
            import_addr_table_addr: u32,
        }, import_descriptor_bytes)) |desc| {
            if (desc.dll_name_addr == 0 or desc.import_addr_table_addr == 0) {
                break;
            }
            const dll_name = std.mem.span(@ptrCast([*:0]u8, &vmem[desc.dll_name_addr - min_addr]));
            const import_name_table = std.mem.span(@ptrCast([*:0]u64, @alignCast(8, &vmem[desc.import_name_table - min_addr])));
            const import_addr_table = @ptrCast([*]u64, @alignCast(8, &vmem[desc.import_addr_table_addr - min_addr]));
            for (import_name_table) |import_name_base, i| {
                const import_name = std.mem.span(@ptrCast([*:0]u8, &vmem[import_name_base + 2 - min_addr]));
                import_addr_table[i] =
                    @ptrToInt(import_resolve_context.findSymbol(dll_name, import_name) orelse return error.UnresolvedImport);
            }
        }
        log("Imports done", .{});
    }

    // Exports?
    blk: {
        const exports_entry = coff_file.pe_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exports_entry.size == 0)
            break :blk;
        const export_descriptor_bytes = vmem[exports_entry.virtual_address - min_addr ..][0..exports_entry.size];
        // TODO: Exports
        _ = export_descriptor_bytes;
        @panic("TODO: Exports");
    }

    for (coff_file.sections.items) |s| {
        const header = s.header;

        const section_mem = blk: {
            var result = vmem[header.virtual_address - min_addr ..][0..header.misc.virtual_size];
            result.len += 0xFFF;
            result.len &= ~@as(usize, 0xFFF);
            break :blk result;
        };

        if (header.characteristics & 0x02000000 != 0) { // Section can be discarded after loading
            log("Unmapping section at 0x{X} with size 0x{X}", .{ @ptrToInt(section_mem.ptr), section_mem.len });
            std.os.munmap(section_mem);
            continue;
        }

        const prot_flags = blk: {
            var result: u32 = std.os.PROT.READ;
            if (header.characteristics & std.coff.IMAGE_SCN_MEM_EXECUTE != 0)
                result |= std.os.PROT.EXEC;
            if (header.characteristics & std.coff.IMAGE_SCN_MEM_WRITE != 0)
                result |= std.os.PROT.WRITE;
            break :blk result;
        };

        log("Keeping section at 0x{X} with size 0x{X}, new prot flags: 0x{X}", .{ @ptrToInt(section_mem.ptr), section_mem.len, prot_flags });

        try std.os.mprotect(
            section_mem,
            prot_flags,
        );
    }
    log("Section permissions set", .{});

    return coff_file.pe_header.entry_addr +% load_delta +% coff_file.pe_header.image_base;
}
