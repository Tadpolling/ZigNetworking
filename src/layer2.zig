// Stores relevant structs and packets for the layer 2 of the OSI model.
const std = @import("std");
const posix = std.posix;
const Networking = @import("./networking.zig");

pub const Ethernet2_Header = extern struct {
    destination_mac: Networking.MAC_Address,
    source_mac: Networking.MAC_Address,
    ether_type: u16,

    pub fn to_network(self: Ethernet2_Header, buffer: []u8) !void {
        @memcpy(buffer[0..@sizeOf(Networking.MAC_Address)], self.destination_mac.to_network());
        @memcpy(buffer[@sizeOf(Networking.MAC_Address) .. 2 * @sizeOf(Networking.MAC_Address)], self.source_mac.to_network());
        std.mem.writeInt(u16, buffer[2 * @sizeOf(Networking.MAC_Address) .. @sizeOf(Ethernet2_Header)], self.ether_type, .big);
    }

    pub fn print(self: Ethernet2_Header) void {
        std.debug.print("Ethernet message type: 0x{x}\n", .{std.mem.nativeToBig(u16, self.ether_type)});
        std.debug.print("Destination MAC: {}\n", .{self.destination_mac});
        std.debug.print("Source MAC: {}\n", .{self.source_mac});
    }

    pub fn create_broadcast_header(ethernet_type: u16) !Ethernet2_Header {
        return Ethernet2_Header{ .destination_mac = Networking.MAC_Address.broadcast_mac, .source_mac = try Networking.MAC_Address.getWifiMac(std.heap.page_allocator), .ether_type = ethernet_type };
    }
};

pub const ARP_Packet = extern struct {
    const ETH_P_ARP: u16 = 0x0806;
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

    pub fn to_network(self: ARP_Packet, buffer: []u8) !void {
        std.mem.writeInt(u16, buffer[0..@sizeOf(u16)], self.hardware_type, .big);
        std.mem.writeInt(u16, buffer[@sizeOf(u16) .. 2 * @sizeOf(u16)], self.protocol_type, .big);
        std.mem.writeInt(u8, buffer[2 * @sizeOf(u16) .. 2 * @sizeOf(u16) + @sizeOf(u8)], self.hardware_length, .big);
        std.mem.writeInt(u8, buffer[2 * @sizeOf(u16) + @sizeOf(u8) .. 3 * @sizeOf(u16)], self.protocol_length, .big);
        std.mem.writeInt(u16, buffer[3 * @sizeOf(u16) .. 4 * @sizeOf(u16)], self.operation_type, .big);

        @memcpy(buffer[4 * @sizeOf(u16) .. 4 * @sizeOf(u16) + @sizeOf(Networking.MAC_Address)], self.sender_mac.to_network());
        @memcpy(buffer[4 * @sizeOf(u16) + @sizeOf(Networking.MAC_Address) .. 4 * @sizeOf(u16) + @sizeOf(Networking.MAC_Address) + @sizeOf(Networking.IP_Address)], self.sender_ip.to_network());
        @memcpy(buffer[4 * @sizeOf(u16) + @sizeOf(Networking.MAC_Address) + @sizeOf(Networking.IP_Address) .. 4 * @sizeOf(u16) + 2 * @sizeOf(Networking.MAC_Address) + @sizeOf(Networking.IP_Address)], self.destination_mac.to_network());
        @memcpy(buffer[4 * @sizeOf(u16) + 2 * @sizeOf(Networking.MAC_Address) + @sizeOf(Networking.IP_Address) .. 4 * @sizeOf(u16) + 2 * @sizeOf(Networking.MAC_Address) + 2 * @sizeOf(Networking.IP_Address)], self.destination_ip.to_network());
    }
};

pub const ARP_Full_Packet = extern struct {
    ethernet_header: Ethernet2_Header,
    arp_packet: ARP_Packet,

    pub fn to_network(self: ARP_Full_Packet, buff: []u8) !void {
        try self.ethernet_header.to_network(buff[0..@sizeOf(Ethernet2_Header)]);
        try self.arp_packet.to_network(buff[@sizeOf(Ethernet2_Header)..@sizeOf(ARP_Full_Packet)]);
    }
};
