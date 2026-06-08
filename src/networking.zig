// Basic structs and functionality used for networking

const std = @import("std");

pub const MAC_Address = extern struct {
    address: [6]u8,

    pub fn format(
        self: MAC_Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        // Print your custom layout to the provided writer
        for (self.address, 0..) |mac_segment, i| {
            try writer.print("{x}{s}", .{ mac_segment, if (i < self.address.len - 1) ":" else "" });
        }
    }
};

pub const IP_Address = extern struct {
    address: [4]u8,

    pub fn format(
        self: IP_Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        // Print your custom layout to the provided writer
        for (self.address, 0..) |ip_segment, i| {
            try writer.print("{}{s}", .{ ip_segment, if (i < self.address.len - 1) "." else "" });
        }
    }
};
