const std = @import("std");
const Pcap = @import("./pcap.zig");
const Networking = @import("./networking.zig");
const Layer2 = @import("./layer2.zig");

// Import the Npcap C declarations natively into Zig
const pcap = @cImport({
    @cDefine("HAVE_REMOTE", "");
    @cInclude("pcap.h");
});

pub fn main() !void {
    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;

    // 1. Find all available network devices on the system
    var alldevs: ?*pcap.pcap_if_t = null;
    if (pcap.pcap_findalldevs(&alldevs, &errbuf) == -1) {
        std.debug.print("Error finding devices: {s}\n", .{errbuf});
        return error.PcapFindFailed;
    }
    defer pcap.pcap_freealldevs(alldevs);

    // Pick the very first device for this demo (In a real app, let the user select)
    const device = alldevs orelse {
        std.debug.print("No network interfaces found.\n", .{});
        return error.NoInterfaces;
    };
    std.debug.print("Opening device: {s}\n", .{device.name});

    // 2. Open the interface in live injection mode
    const handle = pcap.pcap_open_live(
        device.name,
        65536,  // Snapshot length
        1,      // Promiscuous mode enabled
        1000,   // Read timeout in ms
        &errbuf,
    ) orelse {
        std.debug.print("Failed to open adapter: {s}\n", .{errbuf});
        return error.PcapOpenFailed;
    };
    defer pcap.pcap_close(handle);

    // 3. Construct your raw Layer 2 Broadcast ARP Frame
    var packet = std.mem.zeroes([42]u8);

    // --- Ethernet Header ---
    @memset(packet[0..6], 0xFF);                     // Destination MAC (Broadcast)
    packet[6..12].* = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }; // Fake/Real Sender MAC
    packet[12] = 0x08; packet[13] = 0x06;            // Type: ARP (0x0806)

    // --- ARP Payload ---
    packet[14..16].* = .{ 0x00, 0x01 };               // Hardware: Ethernet
    packet[16..18].* = .{ 0x08, 0x00 };               // Protocol: IPv4
    packet[18] = 6;                                    // MAC Size
    packet[19] = 4;                                    // IP Size
    packet[20..22].* = .{ 0x00, 0x01 };               // Opcode: Request

    @memcpy(packet[22..28], packet[6..12]);            // Sender MAC 
    packet[28..32].* = .{ 192, 168, 1, 50 };           // Sender IP
    @memset(packet[32..38], 0x00);                     // Target MAC (Blank)
    packet[38..42].* = .{ 192, 168, 1, 1 };            // Target IP to resolve

    // 4. Force inject the raw bytes into the network via Npcap kernel driver
    if (pcap.pcap_sendpacket(handle, &packet, packet.len) != 0) {
        const err_msg = pcap.pcap_geterr(handle);
        std.debug.print("Injection error: {s}\n", .{err_msg});
        return error.InjectionFailed;
    }

    std.debug.print("Successfully injected raw ARP frame on Windows via Npcap!\n", .{});
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
