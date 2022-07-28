const std = @import("std");
const rt = @import("rt.zig");

const log = @import("log.zig").scoped(.vfs);

pub var dirents: std.ArrayListUnmanaged(DirectoryEntry) = .{};
var curr_free: i32 = -1;
var dirents_mutex = std.Thread.Mutex{};
var vfs_alloc = std.heap.GeneralPurposeAllocator(.{}){ .backing_allocator = std.heap.page_allocator };

fn deref(idx: i32) *DirectoryEntry {
    std.debug.assert(idx >= 0);
    return &dirents.items[@intCast(usize, idx)];
}

fn allocIdx() !i32 {
    if(curr_free != -1) {
        const result = curr_free;
        curr_free = deref(curr_free).next;
        return result;
    }

    const result = @intCast(i32, dirents.items.len);
    _ = dirents.addOneAssumeCapacity();
    return result;
}

var symdyn_alloc = std.heap.GeneralPurposeAllocator(.{}){ .backing_allocator = std.heap.page_allocator };
var dynstring_alloc = std.heap.GeneralPurposeAllocator(.{}){ .backing_allocator = std.heap.page_allocator };

pub const DirectoryEntry = struct {
    name: []u8,
    next: i32 = -1,
    value: Value,

    const Value = union(enum) {
        newly_created,
        dir: i32, // First dirent
        symlink: []const u16,
        symdyn: []const u16,
        string: []const u16,
        dynstring: []const u16,
        mutex: std.Thread.Mutex,
    };

    const ValueKind = @typeInfo(Value).Union.tag_type.?;

    pub fn get(self: *@This(), comptime kind: ValueKind) ?*@TypeOf(@field(self.value, @tagName(kind))) {
        if(self.value == .newly_created) {
            switch(comptime kind) {
                .dir => {
                    self.value = .{ .dir = -1 };
                    return &self.value.dir;
                },
                .mutex => {
                    self.value = .{ .mutex = .{} };
                    return &self.value.mutex;
                },
                .symlink => {
                    self.value = .{ .symlink = &[_]u16{} };
                    return &self.value.symlink;
                },
                .string => {
                    self.value = .{ .string = &[_]u16{} };
                    return &self.value.string;
                },
                else => @compileError("Bad value kind for get()"),
            }
        }
        if(comptime (kind == .symlink) and self.value == .symdyn)
            return &self.value.symdyn;

        if(comptime (kind == .string) and self.value == .dynstring)
            return &self.value.dynstring;

        if(self.value == kind) {
            return &@field(self.value, @tagName(kind));
        }
        return null;
    }

    pub fn setSymlinkDyn(self: *@This(), value: []const u16) !void {
        const new_mem = try symdyn_alloc.allocator().dupe(u16, value);
        switch(self.value) {
            .newly_created, .symlink => self.value = .{ .symdyn = new_mem },
            .symdyn => |*d| {
                symdyn_alloc.allocator().free(d.*);
                d.* = new_mem;
            },
            else => @panic("bad value type"),
        }
    }

    pub fn setStringDyn(self: *@This(), value: []const u16) !void {
        const new_mem = try dynstring_alloc.allocator().dupe(u16, value);
        switch(self.value) {
            .newly_created, .string => self.value = .{ .dynstring = new_mem },
            .dynstring => |*d| {
                dynstring_alloc.allocator().free(d.*);
                d.* = new_mem;
            },
            else => @panic("bad value type"),
        }
    }
};

pub var fs_root: i32 = -1;
pub var object_root: i32 = -1;
pub var registry_root: i32 = -1;

pub fn caseInsensitiveEq(lhs: u21, rhs: u21) bool {
    if(lhs <= 0x7F and rhs <= 0x7F) {
        return std.ascii.toLower(@intCast(u8, lhs)) == std.ascii.toLower(@intCast(u8, rhs));
    }
    return lhs == rhs;
}

fn compareNames(path: *[]const u8, name: []const u8) bool {
    var path_idx: usize = 0;
    var name_idx: usize = 0;
    while(true) {
        const curr_path = path.*[path_idx..];
        const curr_name = name[name_idx..];

        if(curr_path.len == 0 or curr_path[0] == '\\') {
            if(curr_name.len == 0) {
                path.* = curr_path;
                return true;
            } else {
                return false;
            }
        }
        if(curr_name.len == 0) return false;

        const path_len = std.unicode.utf8ByteSequenceLength(curr_path[0]) catch @panic("aaa");
        const name_len = std.unicode.utf8ByteSequenceLength(curr_name[0]) catch @panic("aaa");

        if(path_len > curr_path.len) @panic("aaa");
        if(name_len > curr_name.len) @panic("aaa");

        const path_cp = std.unicode.utf8Decode(curr_path[0..path_len]) catch @panic("aaa");
        const name_cp = std.unicode.utf8Decode(curr_name[0..name_len]) catch @panic("aaa");

        if(!caseInsensitiveEq(path_cp, name_cp))
            return false;

        path_idx += path_len;
        name_idx += name_len;
    }
}

// If the entry is found or created, the chars are consumed
pub fn resolveSingleStep(current_dir: *i32, buf: *[]const u8, create: bool) !*DirectoryEntry {
    var dirent_tail = current_dir;
    while(dirent_tail.* != -1) {
        const dirent = deref(dirent_tail.*);
        dirent_tail = &dirent.next;

        if(!compareNames(buf, dirent.name))
            continue;

        return dirent;
    }

    if(create) {
        const name = try vfs_alloc.allocator().dupe(u8, split(buf, '\\'));
        log("-> Could not find it, creating new dirent with name '{s}'", .{name});
        log("  -> Remaining search string '{s}'", .{buf.*});
        const next = try allocIdx();
        dirent_tail.* = next;
        const result = deref(next);
        result.* = .{
            .name = name,
            .value = .newly_created,
        };
        return result;
    } else {
        return error.DoesNotExist;
    }
}

pub fn resolveInDir(current_dir_c: *i32, buffer: *[]const u8, create_deep: bool) !*DirectoryEntry {
    var current_dir = current_dir_c;
    while(true) {
        log("Resolving: '{s}'", .{buffer.*});
        const res = try resolveSingleStep(current_dir, buffer, create_deep);
        if(takeStr(buffer, "\\")) {
            current_dir = res.get(.dir) orelse @panic("wtf");
            if(buffer.len == 0) return res;
            continue;
        }
        if(buffer.len > 0) {
            log("Remaining: '{s}'", .{buffer.*});
            @panic("resolveInDir char not consumed");
        }
        return res;
    }
}

fn takeStr(buffer: *[]const u8, str: []const u8) bool {
    if(std.mem.startsWith(u8, buffer.*, str)) {
        buffer.* = buffer.*[str.len..];
        return true;
    }
    return false;
}

fn split(buffer: *[]const u8, delim: u8) []const u8 {
    const idx = std.mem.indexOfScalar(u8, buffer.*, delim) orelse buffer.len;
    const retval = buffer.*[0..idx];
    buffer.* = buffer.*[idx..];
    return retval;
}

pub fn resolve(buffer: *[]const u8, create_deep: bool) !*DirectoryEntry {
    dirents_mutex.lock();
    errdefer dirents_mutex.unlock();

    try dirents.ensureUnusedCapacity(vfs_alloc.allocator(), 100); // Ought to be enough for anybody

    _ = takeStr(buffer, "\\??\\");
    _ = takeStr(buffer, "\\??");
    if(takeStr(buffer, "\\Registry\\")) {
        return resolveInDir(&registry_root, buffer, create_deep);
    }
    if(takeStr(buffer, "C:\\")) {
        return resolveInDir(&fs_root, buffer, create_deep);
    }
    if(takeStr(buffer, "\\")) {
        return resolveInDir(&object_root, buffer, create_deep);
    }
    return resolveInDir(&fs_root, buffer, create_deep);
}

pub fn close(dirent: *DirectoryEntry) void {
    _ = dirent;
    dirents_mutex.unlock();
}

const VALID_HANDLE: rt.HANDLE = 0xFF000000;

pub fn handle(dirent: *DirectoryEntry) rt.HANDLE {
    // Calculate offset from start of dirent array
    const offset = @ptrToInt(dirent) - @ptrToInt(dirents.items.ptr);
    const idx = offset / @sizeOf(DirectoryEntry);
    return idx | VALID_HANDLE;
}

pub fn openHandle(h: rt.HANDLE) *DirectoryEntry {
    if((h & VALID_HANDLE) != VALID_HANDLE) {
        @panic("Invalid handle");
    }
    const handle_idx = h & ~VALID_HANDLE;
    dirents_mutex.lock();
    return &dirents.items[handle_idx];
}

var resolve_utf8_buffer: [4096]u8 = undefined;

fn transcode(path: []const u16) []const u8 {
    const len = std.unicode.utf16leToUtf8(&resolve_utf8_buffer, path) catch @panic("aaa");
    return resolve_utf8_buffer[0..len];
}

pub fn resolve16In(dir: *i32, path: []const u16, create: bool) !*DirectoryEntry {
    var buf = transcode(path);
    return resolveSingleStep(dir, &buf, create);
}

pub fn resolve16(path: []const u16, create_deep: bool) !*DirectoryEntry {
    var buf = transcode(path);
    return resolve(&buf, create_deep);
}

pub fn resolve8(path: []const u8, create_deep: bool) !*DirectoryEntry {
    var buf = path;
    return resolve(&buf, create_deep);
}

const writer = std.io.getStdErr().writer();

fn dumpDir(dirent_c: i32, depth: usize) @TypeOf(writer).Error!void {
    var dirent = dirent_c;
    while(dirent != -1) {
        var ent = &dirents.items[@intCast(usize, dirent)];
        try writer.writeByteNTimes(' ', depth);
        try writer.writeAll("> ");
        for(ent.name) |b| {
            try writer.writeByte(@truncate(u8, b));
        }
        try writer.writeByte('\n');

        if(ent.value == .dir) {
            try dumpDir(ent.value.dir, depth + 1);
        }
        dirent = ent.next;
    }
}

pub fn dump() !void {
    try writer.writeAll("fs:\n");
    try dumpDir(fs_root, 0);
    try writer.writeAll("objects:\n");
    try dumpDir(object_root, 0);
    try writer.writeAll("registry:\n");
    try dumpDir(registry_root, 0);
}
