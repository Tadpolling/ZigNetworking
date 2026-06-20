// Basic structs and functionality used for networking

const std = @import("std");

const win32 = @import("win32");
const foundation = win32.foundation;
const ip_helper = win32.network_management.ip_helper;

const NO_ERROR = foundation.NO_ERROR;
const ERROR_BUFFER_OVERFLOW = foundation.ERROR_BUFFER_OVERFLOW;
const IP_ADAPTER_ADDRESSES_LH = ip_helper.IP_ADAPTER_ADDRESSES_LH;
const GetAdaptersAddresses = ip_helper.GetAdaptersAddresses;

const MIB_IF_TYPE_LOOPBACK = ip_helper.MIB_IF_TYPE_LOOPBACK;

const AdapterOptions = struct {
    exclude_loopback: bool = false,
};

const IF_TYPE_IEEE80211 = 71; // Standard Windows value for Wi-Fi (802.11)
const IfOperStatusUp = 1;

pub const MAC_Address = extern struct {
    pub const broadcast_mac: MAC_Address = MAC_Address{ .address = [_]u8{0xFF} ** 6 };
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

    pub fn to_network(self: MAC_Address) []const u8 {
        return &self.address;
    }

    pub fn getWifiMac(allocator: std.mem.Allocator) !MAC_Address {
        // 1. Allocate a dynamic buffer to avoid the overflow bug mentioned earlier
        var size: u32 = 15000;
        var buf = try allocator.alloc(u8, size);
        defer allocator.free(buf);

        var res = GetAdaptersAddresses(.INET, .{}, null, @alignCast(@ptrCast(buf.ptr)), &size);

        if (res == @intFromEnum(ERROR_BUFFER_OVERFLOW)) {
            buf = try allocator.realloc(buf, size);
            res = GetAdaptersAddresses(.INET, .{}, null, @alignCast(@ptrCast(buf.ptr)), &size);
        }

        if (res != @intFromEnum(NO_ERROR)) {
            return error.OSError;
        }

        // 2. Loop through the adapters and find the Wi-Fi card
        var node: ?*IP_ADAPTER_ADDRESSES_LH = @alignCast(@ptrCast(buf.ptr));
        while (node) |adapter| : (node = node.?.Next) {
            // Check if the adapter is an 802.11 Wireless interface
            if (adapter.IfType == IF_TYPE_IEEE80211 and @intFromEnum(adapter.OperStatus) == IfOperStatusUp) {
                return MAC_Address{ .address = adapter.PhysicalAddress[0..6].* };
                // .data = adapter.PhysicalAddress[0..6].*,
                // .is_loopback = false,
            }
        }

        return error.NoDevice; // No Wi-Fi adapter found
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

    pub fn to_network(self: IP_Address) []const u8 {
        return &self.address;
    }
};
