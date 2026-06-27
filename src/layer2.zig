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
    hardware_type: u16, // Type of network, e.g. ethernet is 1
    protocol_type: u16, // type depending on if it is IPv4 (has value 0x800) or otherwise
    hardware_length: u8, // length of hardware address (MAC is 6 bytes so value is 6)
    protocol_length: u8, // length of network address (IP has 4 bytes so value is 4)
    operation_type: u16, // 1 for request, 2 for response
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

    pub fn create_arp_packet(ip_requested: Networking.IP_Address) !ARP_Full_Packet {
        const ethernet_header = try Ethernet2_Header.create_broadcast_header(ARP_Packet.ETH_P_ARP);
        const current_ip = (try Networking.IP_Address.get_current_ip()).?;
        const arp_msg = ARP_Packet{ .hardware_type = 0x001, .protocol_type = 0x0800, .hardware_length = 6, .protocol_length = 4, .operation_type = 0x001, .sender_mac = try Networking.MAC_Address.getWifiMac(std.heap.page_allocator), .sender_ip = current_ip, .destination_mac = .{ .address = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }, .destination_ip = ip_requested };
        return ARP_Full_Packet{ .ethernet_header = ethernet_header, .arp_packet = arp_msg };
    }
};

pub const TLV = struct {
    // Type is 7 bits, length is 9 bits
    type_length: u16,

    // Length is the length seen in the length field
    value: []const u8,

    pub inline fn get_length(self: TLV) u16 {
        return get_length_from_type_length(self.type_length);
    }

    pub inline fn get_length_from_type_length(type_length: u16) u16 {
        // We want to get the last 9 bits and ignore the first 7 bits so we do a logical and removing
        // the first 7 bits.
        return 0x01FF & type_length;
    }

    pub inline fn get_type(self: TLV) u8 {
        // shifting to the right to remove the first 9 bits and then downsizing to be a u8
        return @intCast(self.type_length >> 9);
    }

    pub fn create_TLV(type_length: u16, value_array: []const u8) !TLV {
        return TLV{ .type_length = type_length, .value = value_array };
    }

    pub inline fn is_final_tlv(self: TLV) bool {
        return self.type_length == 0;
    }

    pub fn print(self: TLV) void {
        std.debug.print("Type: {d}\nLength: {d}\n", .{ self.get_type(), self.get_length() });
        std.debug.print("Value: ", .{});
        for (self.value) |byte| {
            std.debug.print("{x:0>2} ", .{byte});
        }
        std.debug.print("\n", .{});
    }
};

pub const LLDPDU = struct {
    tlv_array: []TLV,

    pub fn create_lldpdu(buff: []const u8) !LLDPDU {
        var should_continue = true;
        var tlv_list = std.ArrayList(TLV);
        var current_tlv: TLV = undefined;
        var buff_length: u16 = undefined;
        var type_length: u16 = undefined;
        while (should_continue) {
            type_length = @intCast(buff[0..2]);
            buff_length = TLV.get_length_from_type_length(type_length);
            current_tlv = TLV.create_TLV(type_length, buff[0..buff_length]);
            if (current_tlv.is_final_tlv()) should_continue = false;
            tlv_list.addOne(current_tlv);
        }

        return LLDPDU{ .tlv_array = try tlv_list.toOwnedSlice() };
    }
};

pub const LLDP = struct {
    ethernet_header: Ethernet2_Header,
    lldpdu: LLDPDU,

    pub fn parse_lldp_packet(buff: []const u8) !LLDP {
        const ethernet_header = Ethernet2_Header{ .destination_mac = Networking.MAC_Address{ .address = buff[0..6] }, .source_mac = Networking.MAC_Address{ .address = buff[6..12] }, .ether_type = @intCast(buff[12..14]) };
        const lldpu = LLDPDU.create_lldpdu(buff[14..]);
        return LLDP{ .ethernet_header = ethernet_header, .lldpdu = lldpu };
    }
};
