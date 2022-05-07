const std = @import("std");
const os = std.os;

const PE = @import("common/PE.zig");
const ntdll = @import("common/ntdll.zig");
const rt = @import("common/rt.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){
    .backing_allocator = std.heap.page_allocator,
};

const ResolveContext = struct {
    fn isBuiltinModuleName(module_name: []const u8) bool {
        if(std.mem.eql(u8, module_name, "ntdll.dll")) {
            return true;
        }
        return false;
    }

    fn resolveBuiltinSymbol(symbol_name: []const u8) ?*const anyopaque {
        return ntdll.builtin_symbols.get(symbol_name);
    }

    pub fn findSymbol(module_name: []const u8, symbol_name: []const u8) ?*const anyopaque {
        if(isBuiltinModuleName(module_name)) {
            return resolveBuiltinSymbol(symbol_name);
        }
        return null;
    }
};

pub fn toNullTerminatedUTF16Buffer(comptime ascii: []const u8) [ascii.len:0]u16 {
    comptime var result: []const u16 = &[_]u16{};
    inline for(ascii) |chr| {
        result = result ++ &[_]u16{chr};
    }
    result = result ++ [_]u16{0};
    return result[0..ascii.len:0].*;
}

var smss_path = toNullTerminatedUTF16Buffer("C:\\Windows\\system32\\smss.exe");
var smss_command_line = toNullTerminatedUTF16Buffer("C:\\Windows\\system32\\smss.exe");

pub fn main() !void {
    try rt.init(&smss_path, &smss_command_line);

    // launch Smss.exe
    var smss = try std.fs.cwd().openFile("test/smss.exe", .{});
    defer smss.close();

    const smss_entry = try PE.load(smss, gpa.allocator(), ResolveContext);
    std.debug.print("Calling smss.exe entry @ 0x{X}\n", .{smss_entry});
    _ = rt.call_entry(smss_entry);
}