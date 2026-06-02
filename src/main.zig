const std = @import("std");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const file = try std.fs.cwd().openFile("sample-packets/arp-one.pcap", .{});
    defer _ = file.close();

    const reader = file.reader();

    const buffer = try reader.readAllAlloc(allocator, 10000);
    defer allocator.free(buffer);
    std.debug.print("Got an input of size {d}\n", .{buffer.len});
    std.debug.print("Pcap Size is {d}\n", .{@sizeOf(PcapHeader)});

    const pcap_header = std.mem.bytesToValue(PcapHeader, buffer[0..@sizeOf(PcapHeader)]);
    pcap_header.print_information();
    const body = buffer[@sizeOf(PcapHeader)..];
    std.debug.print("Now starting to read packets\n", .{});

    const packet_header = std.mem.bytesToValue(PcapPacketRecordHeader, body[0..@sizeOf(PcapPacketRecordHeader)]);
    std.debug.print("Pcap packet header Size is {d}\n", .{@sizeOf(PcapPacketRecordHeader)});
    packet_header.print();

    const ethernet_packet = body[@sizeOf(PcapPacketRecordHeader)..];
    std.debug.print("Ethernet header size: {}\n", .{@sizeOf(Ethernet2_Header)});

    const ethernet_header = std.mem.bytesToValue(Ethernet2_Header, ethernet_packet[0..@sizeOf(Ethernet2_Header)]);
    ethernet_header.print();

    const arp_packet = std.mem.bytesToValue(ARP_Packet, ethernet_packet[@sizeOf(Ethernet2_Header)..]);
    arp_packet.print();
}

const PcapHeader = extern struct {
    const PCAP_MAGIC_NUMBER = 0xA1B2C3D4;
    magic_number: u32,
    major_version: u16,
    minor_version: u16,
    reserved1: u32,
    reserved2: u32,
    snaplen: u32,
    random_shit: u32,

    pub fn print_information(self: PcapHeader) void {
        std.debug.print("Pcap Version is {d}.{d}\n", .{ self.major_version, self.minor_version });
        std.debug.print("Maximum packet size is less than {d} bytes \n", .{std.mem.nativeToBig(u32, self.snaplen)});
        std.debug.print("Is packet valid? {}\n", .{self.validate_header()});
    }

    pub fn validate_header(self: PcapHeader) bool {
        if (self.reserved1 != 0 or self.reserved2 != 0)
            return false;
        if (self.magic_number != PCAP_MAGIC_NUMBER)
            return false;
        return true;
    }
};

const PcapPacketRecordHeader = extern struct {
    timestamp_seconds: u32,
    timestamp_microseconds: u32,
    captured_packet_length: u32,
    original_packet_length: u32,
    pub fn print(self: PcapPacketRecordHeader) void {
        std.debug.print("Captured packet length {d}\n", .{self.captured_packet_length});
    }
};

const Ethernet2_Header = extern struct {
    destination_mac: MAC_Address,
    source_mac: MAC_Address,
    ether_type: u16,
    pub fn print(self: Ethernet2_Header) void {
        std.debug.print("Ethernet message type: 0x{x}\n", .{std.mem.nativeToBig(u16, self.ether_type)});
        std.debug.print("Destination MAC: {}\n", .{self.destination_mac});
        std.debug.print("Source MAC: {}\n", .{self.source_mac});
    }
};

const MAC_Address = extern struct {
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

const IP_Address = extern struct {
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

const ARP_Packet = extern struct {
    hardware_type: u16,
    protocol_type: u16,
    hardware_length: u8,
    protocol_length: u8,
    operation_type: u16,
    sender_mac: MAC_Address,
    sender_ip: IP_Address,
    destination_mac: MAC_Address,
    destination_ip: IP_Address,

    pub fn print(self: ARP_Packet) void {
        std.debug.print("ARP Packet Information: \n", .{});
        std.debug.print("Hardware Type: {}\n", .{std.mem.nativeToBig(u16, self.hardware_type)});
        std.debug.print("Protocol Type: 0x{x}\n", .{std.mem.nativeToBig(u16, self.protocol_type)});
        std.debug.print("Source MAC: {}\n", .{self.sender_mac});
        std.debug.print("Source IP: {}\n", .{self.sender_ip});
        std.debug.print("Destination MAC: {}\n", .{self.destination_mac});
        std.debug.print("Destination IP: {}\n", .{self.destination_ip});
    }
};

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
