// Stores relevant structs and packets for the layer 2 of the OSI model.
const std = @import("std");
const Networking = @import("./networking.zig");

pub const Ethernet2_Header = extern struct {
    destination_mac: Networking.MAC_Address,
    source_mac: Networking.MAC_Address,
    ether_type: u16,
    pub fn print(self: Ethernet2_Header) void {
        std.debug.print("Ethernet message type: 0x{x}\n", .{std.mem.nativeToBig(u16, self.ether_type)});
        std.debug.print("Destination MAC: {}\n", .{self.destination_mac});
        std.debug.print("Source MAC: {}\n", .{self.source_mac});
    }
};

pub const ARP_Packet = extern struct {
    hardware_type: u16,
    protocol_type: u16,
    hardware_length: u8,
    protocol_length: u8,
    operation_type: u16,
    sender_mac: Networking.MAC_Address,
    sender_ip: Networking.IP_Address,
    destination_mac: Networking.MAC_Address,
    destination_ip: Networking.IP_Address,

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
