// Basic structs and functionality used for networking

const std = @import("std");

const win32 = @import("win32");
const foundation = win32.foundation;
const ip_helper = win32.network_management.ip_helper;

// Pull in the official Windows headers directly
const c = @cImport({
    @cInclude("winsock2.h");
    @cInclude("iphlpapi.h");
    @cInclude("ws2tcpip.h"); // For InetNtopA

});

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

// Native Npcap structures and signatures
const pcap_addr_t = extern struct {
    next: ?*pcap_addr_t,
    addr: ?*std.posix.sockaddr,
    netmask: ?*std.posix.sockaddr,
    broadaddr: ?*std.posix.sockaddr,
    dstaddr: ?*std.posix.sockaddr,
};

const pcap_if_t = extern struct {
    next: ?*pcap_if_t,
    name: [*:0]const u8,
    description: ?[*:0]const u8,
    addresses: ?*pcap_addr_t,
    flags: u32,
};

extern fn pcap_findalldevs(alldevs: *?*pcap_if_t, errbuf: [*]u8) c_int;
extern fn pcap_freealldevs(alldevs: ?*pcap_if_t) void;

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

    pub fn get_current_ip() !?IP_Address {
        var buffer align(@alignOf(win32_struct.IP_ADAPTER_ADDRESSES)) = [_]u8{0} ** 15000;
        var size: u32 = buffer.len;

        if (win32_struct.GetAdaptersAddresses(win32_struct.AF_UNSPEC, 0x000E, null, @ptrCast(&buffer), &size) != 0) {
            return error.Win32Error;
        }

        var adapter: ?*win32_struct.IP_ADAPTER_ADDRESSES = @ptrCast(&buffer);
        while (adapter) |curr| : (adapter = curr.*.Next) {
            var unicast = curr.*.FirstUnicastAddress;

            // No more @ptrCast or alignment warnings needed here anymore!
            while (unicast) |addr| : (unicast = addr.*.Next) {
                const sa = addr.*.Address.lpSockaddr orelse continue;

                if (sa.*.family == win32_struct.AF_INET) {
                    // The IPv4 octets live exactly at indices 2 through 5 inside the raw sockaddr layout
                    const ip = sa.*.data[2..6];
                    // Inside your while loop, after extracting the `ip` bytes:
                    const is_loopback = (ip[0] == 127);
                    const is_apipa = (ip[0] == 169 and ip[1] == 254);

                    if (!is_loopback and !is_apipa) {
                        // This is a valid physical or virtual network interface IP!
                        return IP_Address{ .address = ip.* };
                    }
                }
            }
        }
        return null;
    }

    pub fn to_network(self: IP_Address) []const u8 {
        return &self.address;
    }
};

const windows = std.os.windows;

const win32_struct = struct {
    pub const AF_INET = 2;
    pub const AF_UNSPEC = 0;

    // Properly name the inner structure so 'Next' has the exact same type and alignment
    pub const IP_ADAPTER_UNICAST_ADDRESS = extern struct {
        Length: u32,
        Flags: u32,
        Next: ?*IP_ADAPTER_UNICAST_ADDRESS,
        Address: extern struct { lpSockaddr: ?*extern struct { family: u16, data: [14]u8 }, len: c_int },
    };

    pub const IP_ADAPTER_ADDRESSES = extern struct {
        Length: u32,
        IfIndex: u32,
        Next: ?*IP_ADAPTER_ADDRESSES,
        AdapterName: ?[*:0]u8,
        FirstUnicastAddress: ?*IP_ADAPTER_UNICAST_ADDRESS,
    };

    pub extern "iphlpapi" fn GetAdaptersAddresses(
        Family: u32,
        Flags: u32,
        Reserved: ?*anyopaque,
        AdapterAddresses: ?*IP_ADAPTER_ADDRESSES,
        SizePointer: *u32,
    ) callconv(windows.WINAPI) u32;
};
