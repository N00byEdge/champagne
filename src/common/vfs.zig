const std = @import("std");
const rt = @import("rt.zig");

fn CodePointPeeker(comptime T: type) type {
    return struct {
        impl: T,
        peeked: ?u21 = null,

        fn peek(self: *@This()) ?u21 {
            if(self.peeked) |p| {
                return p;
            }
            self.peeked = self.impl.nextCodepoint() catch @panic(".");
            return self.peeked;
        }

        fn next(self: *@This()) ?u21 {
            const res = self.peek();
            self.peeked = null;
            return res;
        }

        fn peekIs(self: *@This(), value: u21) bool {
            if(self.peek()) |p| {
                if(p == value) return true;
            }
            return false;
        }

        fn take(self: *@This(), value: u21) bool {
            if(self.peekIs(value)) {
                _ = self.next();
                return true;
            }
            return false;
        }

        fn peekString(self: *@This(), value: []const u8) bool {
            var copy = self.*;
            for(value) |b| {
                if(!copy.take(b)) {
                    return false;
                }
            }
            return true;
        }

        fn takeString(self: *@This(), value: []const u8) bool {
            if(self.peekString(value)) {
                for(value) |b| {
                    std.debug.assert(self.take(b));
                }
                return true;
            }
            return false;
        }
    };
}

var dirents: std.ArrayListUnmanaged(DirectoryEntry) = .{};
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

pub const DirectoryEntry = struct {
    name_code_points: []u21,
    next: i32 = -1,
    value: union(enum) {
        newly_created,
        dir: i32, // First dirent
        mutex: std.Thread.Mutex,
    },
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

// If the entry is found or created, the chars are consumed
pub fn resolveSingleStep(current_dir: *i32, cpp: anytype, create: bool) !*DirectoryEntry {
    var dirent_tail = current_dir;
    while(dirent_tail.* != -1) blk: {
        const dirent = deref(dirent_tail.*);
        dirent_tail = &dirent.next;

        var match_cpp = cpp.*;
        for(dirent.name_code_points) |name_cp| {
            if(!caseInsensitiveEq(match_cpp.next() orelse break :blk, name_cp))
                break :blk;
        }

        if(!match_cpp.peekIs('\\')) {
            continue;
        }

        cpp.* = match_cpp;
        return dirent;
    }

    if(create) {
        var cp_buf = std.ArrayListUnmanaged(u21){};
        while(cpp.peek()) |cp| {
            if(cp == '\\') {
                break;
            }
            try cp_buf.append(vfs_alloc.allocator(), cpp.next() orelse unreachable);
        }
        const next = try allocIdx();
        dirent_tail.* = next;
        const result = deref(next);
        result.* = .{
            .name_code_points = cp_buf.toOwnedSlice(vfs_alloc.allocator()),
            .value = .newly_created,
        };
        return result;
    } else {
        return error.DoesNotExist;
    }
}

pub fn resolveInDir(current_dir_c: *i32, cpp: anytype, create_deep: bool) !*DirectoryEntry {
    var current_dir = current_dir_c;
    while(true) {
        const res = try resolveSingleStep(current_dir, cpp, create_deep);
        if(cpp.next()) |n| {
            if(n != '\\') {
                @panic("resolveInDir char not consumed");
            }
            switch(res.value) {
                .newly_created => {
                    if(create_deep) {
                        res.value = .{.dir = -1};
                        current_dir = &res.value.dir;
                    } else {
                        return error.DoesNotExist;
                    }
                },
                .dir => |*d| current_dir = d,
                else => return error.NotDirectory,
            }
        } else {
            return res;
        }
    }
}

pub fn resolve(cpp: anytype, create_deep: bool) !*DirectoryEntry {
    dirents_mutex.lock();
    errdefer dirents_mutex.unlock();

    try dirents.ensureUnusedCapacity(vfs_alloc.allocator(), 100); // Ought to be enough for anybody

    _ = cpp.takeString("\\??\\");
    if(cpp.takeString("\\Registry\\")) {
        return resolveInDir(&registry_root, cpp, create_deep);
    }
    if(cpp.takeString("C:\\")) {
        return resolveInDir(&fs_root, cpp, create_deep);
    }
    if(cpp.take('\\')) {
        return resolveInDir(&object_root, cpp, create_deep);
    }
    return resolveInDir(&fs_root, cpp, create_deep);
}

pub fn close(dirent: *DirectoryEntry) void {
    _ = dirent;
    dirents_mutex.unlock();
}

const VALID_HANDLE = 0xFF000000;

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
    return dirents.items[handle_idx];
}

pub fn resolve16In(dir: *i32, path: []const u16, create: bool) !*DirectoryEntry {
    var it = std.unicode.Utf16LeIterator.init(path);
    var cpp = CodePointPeeker(@TypeOf(it)){.impl = it};
    return resolveSingleStep(dir, &cpp, create);
}

pub fn resolve16(path: []const u16, create_deep: bool) !*DirectoryEntry {
    var it = std.unicode.Utf16LeIterator.init(path);
    var cpp = CodePointPeeker(@TypeOf(it)){.impl = it};
    return resolve(&cpp, create_deep);
}

pub fn resolve8(path: []const u8, create_deep: bool) !*DirectoryEntry {
    var it = std.unicode.Utf8Iterator.init(path);
    var cpp = CodePointPeeker(@TypeOf(it)){.impl = it};
    return resolve(&cpp, create_deep);
}
