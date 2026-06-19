const std = @import("std");
const Pcap = @import("./pcap.zig");
const Networking = @import("./networking.zig");
const Layer2 = @import("./layer2.zig");

pub fn main() !void {
    try Pcap.run();
}

// pub fn main() !void {
//     // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
//     std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

//     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//     const allocator = gpa.allocator();
//     defer _ = gpa.deinit();

//     const file = try std.fs.cwd().openFile("sample-packets/arp-one.pcap", .{});
//     defer _ = file.close();

//     const reader = file.reader();

//     const buffer = try reader.readAllAlloc(allocator, 10000);
//     defer allocator.free(buffer);
//     std.debug.print("Got an input of size {d}\n", .{buffer.len});
//     std.debug.print("Pcap Size is {d}\n", .{@sizeOf(Pcap.PcapHeader)});

//     const pcap_header = Pcap.PcapHeader.create_pcap_header(buffer[0..@sizeOf(Pcap.PcapHeader)]);
//     // const pcap_header1 = std.mem.bytesToValue(PcapHeader, buffer[0..@sizeOf(PcapHeader)]);
//     pcap_header.print_information();
//     const body = buffer[@sizeOf(Pcap.PcapHeader)..];
//     std.debug.print("Now starting to read packets\n", .{});

//     const packet_header = std.mem.bytesToValue(Pcap.PcapPacketRecordHeader, body[0..@sizeOf(Pcap.PcapPacketRecordHeader)]);
//     std.debug.print("Pcap packet header Size is {d}\n", .{@sizeOf(Pcap.PcapPacketRecordHeader)});
//     packet_header.print();

//     const ethernet_packet = body[@sizeOf(Pcap.PcapPacketRecordHeader)..];
//     std.debug.print("Ethernet header size: {}\n", .{@sizeOf(Layer2.Ethernet2_Header)});

//     const ethernet_header = std.mem.bytesToValue(Layer2.Ethernet2_Header, ethernet_packet[0..@sizeOf(Layer2.Ethernet2_Header)]);
//     ethernet_header.print();

//     const arp_packet = std.mem.bytesToValue(Layer2.ARP_Packet, ethernet_packet[@sizeOf(Layer2.Ethernet2_Header)..]);
//     arp_packet.print();
// }

// test "simple test" {
//     var list = std.ArrayList(i32).init(std.testing.allocator);
//     defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
//     try list.append(42);
//     try std.testing.expectEqual(@as(i32, 42), list.pop());
// }
