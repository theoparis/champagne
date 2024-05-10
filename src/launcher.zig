const std = @import("std");
const os = std.os;

const PE = @import("common/PE.zig");
const ntdll = @import("common/ntdll.zig");
const rt = @import("common/rt.zig");
const vfs = @import("common/vfs.zig");

const log_lib = @import("common/log.zig");
const logger = log_lib.scoped(.launcher);

pub fn log(
    comptime level: std.log.Level,
    comptime scope: anytype,
    comptime fmt: []const u8,
    args: anytype,
) void {
    _ = level;
    _ = scope;
    _ = fmt;
    _ = args;
    //log_lib.scoped(scope)(@tagName(level) ++ ": " ++ fmt, args);
}

const ResolveContext = @import("common/symbols.zig").ResolveContext;

var smss_path = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Windows\\system32\\smss.exe").*;
var smss_command_line = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Windows\\system32\\smss.exe").*;

fn setSymlink(path: []const u8, comptime value: []const u8) !void {
    const node = try vfs.resolve8(path, true);
    defer vfs.close(node);
    node.get(.symlink).?.* = std.unicode.utf8ToUtf16LeStringLiteral(value);
}

fn doVfsInit() !void {
    try setSymlink("\\KnownDlls\\KnownDllPath", "C:\\Windows\\System32");
    try setSymlink("\\KnownDlls32\\KnownDllPath", "C:\\Windows\\System32");
}

pub fn main() !void {
    try rt.init(&smss_path, &smss_command_line);

    var ntdll_file = try std.fs.cwd().openFile("test/Windows/System32/ntdll.dll", .{});
    defer ntdll_file.close();

    const ntdll_entry = try PE.load(ntdll_file, ResolveContext);
    _ = ntdll_entry;

    // launch Smss.exe
    var smss = try std.fs.cwd().openFile("test/Windows/System32/smss.exe", .{});
    defer smss.close();

    try doVfsInit();

    const smss_entry = try PE.load(smss, ResolveContext);
    logger("Calling smss.exe entry @ 0x{X}", .{smss_entry});
    _ = rt.call_entry(smss_entry);
}
