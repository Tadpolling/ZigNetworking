// Relevant structs and function to parsing pcap files
const std = @import("std");
const Layer2 = @import("./layer2.zig");
const Networking = @import("./networking.zig");

// Import the Npcap C declarations natively into Zig
const pcap = @cImport({
    @cDefine("HAVE_REMOTE", "");
    @cInclude("pcap.h");
});

// Stores the header of a Pcap File. Only should be one per file.
pub const PcapHeader = extern struct {
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
        std.debug.print("Maximum packet size is less than {d} bytes \n", .{self.snaplen});
        std.debug.print("Is packet valid? {}\n", .{self.validate_header()});
    }

    pub fn validate_header(self: PcapHeader) bool {
        if (self.reserved1 != 0 or self.reserved2 != 0)
            return false;
        if (self.magic_number != PCAP_MAGIC_NUMBER)
            return false;
        return true;
    }

    pub fn create_pcap_header(header_bytes: []u8) PcapHeader {
        const magic_number_start = @offsetOf(PcapHeader, "magic_number");
        const magic_number_end = magic_number_start + @sizeOf(u32);
        const magic_number = std.mem.readInt(u32, header_bytes[magic_number_start..magic_number_end], .little);

        const major_version_start = @offsetOf(PcapHeader, "major_version");
        const major_version_end = major_version_start + @sizeOf(u16);
        const major_version = std.mem.readInt(u16, header_bytes[major_version_start..major_version_end], .little);

        const minor_version_start = @offsetOf(PcapHeader, "minor_version");
        const minor_version_end = minor_version_start + @sizeOf(u16);
        const minor_version = std.mem.readInt(u16, header_bytes[minor_version_start..minor_version_end], .little);

        const reserved1_start = @offsetOf(PcapHeader, "reserved1");
        const reserved1_end = reserved1_start + @sizeOf(u32);
        const reserved1 = std.mem.readInt(u32, header_bytes[reserved1_start..reserved1_end], .little);

        const reserved2_start = @offsetOf(PcapHeader, "reserved2");
        const reserved2_end = reserved2_start + @sizeOf(u32);
        const reserved2 = std.mem.readInt(u32, header_bytes[reserved2_start..reserved2_end], .little);

        const snaplen_start = @offsetOf(PcapHeader, "snaplen");
        const snaplen_end = snaplen_start + @sizeOf(u32);
        const snaplen = std.mem.readInt(u32, header_bytes[snaplen_start..snaplen_end], .little);

        const random_shit_start = @offsetOf(PcapHeader, "random_shit");
        const random_shit_end = random_shit_start + @sizeOf(u32);
        const random_shit = std.mem.readInt(u32, header_bytes[random_shit_start..random_shit_end], .little);

        return .{ .magic_number = magic_number, .major_version = major_version, .minor_version = minor_version, .reserved1 = reserved1, .reserved2 = reserved2, .snaplen = snaplen, .random_shit = random_shit };
    }
};

// Stores the header for each packet stored in the pcap file.
pub const PcapPacketRecordHeader = extern struct {
    timestamp_seconds: u32,
    timestamp_microseconds: u32,
    captured_packet_length: u32,
    original_packet_length: u32,
    pub fn print(self: PcapPacketRecordHeader) void {
        std.debug.print("Captured packet length {d}\n", .{self.captured_packet_length});
    }

    // pub fn create_pcap_record_header(header_bytes: []u8) PcapPacketRecordHeader {
    //     const timestamp_seconds_start = @offsetOf(PcapPacketRecordHeader, "timestamp_seconds");
    //     const timestamp_seconds_end = timestamp_seconds_start + @sizeOf(u32);
    //     const timestamp_seconds = std.mem.readInt(u32, header_bytes[timestamp_seconds_start..timestamp_seconds_end], .little);

    //     const timestamp_microseconds_start = @offsetOf(PcapPacketRecordHeader, "timestamp_microseconds");
    //     const timestamp_microseconds_end = timestamp_microseconds_start + @sizeOf(u16);
    //     const timestamp_microseconds = std.mem.readInt(u16, header_bytes[timestamp_microseconds_start..timestamp_microseconds_end], .little);

    //     const minor_version_start = @offsetOf(PcapHeader, "minor_version");
    //     const minor_version_end = minor_version_start + @sizeOf(u16);
    //     const minor_version = std.mem.readInt(u16, header_bytes[minor_version_start..minor_version_end], .little);

    //     const reserved1_start = @offsetOf(PcapHeader, "reserved1");
    //     const reserved1_end = reserved1_start + @sizeOf(u32);
    //     const reserved1 = std.mem.readInt(u32, header_bytes[reserved1_start..reserved1_end], .little);

    //     const reserved2_start = @offsetOf(PcapHeader, "reserved2");
    //     const reserved2_end = reserved2_start + @sizeOf(u32);
    //     const reserved2 = std.mem.readInt(u32, header_bytes[reserved2_start..reserved2_end], .little);

    //     const snaplen_start = @offsetOf(PcapHeader, "snaplen");
    //     const snaplen_end = snaplen_start + @sizeOf(u32);
    //     const snaplen = std.mem.readInt(u32, header_bytes[snaplen_start..snaplen_end], .little);

    //     const random_shit_start = @offsetOf(PcapHeader, "random_shit");
    //     const random_shit_end = random_shit_start + @sizeOf(u32);
    //     const random_shit = std.mem.readInt(u32, header_bytes[random_shit_start..random_shit_end], .little);

    //     return .{ .magic_number = magic_number, .major_version = major_version, .minor_version = minor_version, .reserved1 = reserved1, .reserved2 = reserved2, .snaplen = snaplen, .random_shit = random_shit };
    // }
};

pub const Pcap_Handle = struct {
    device_name: [*c]u8,
    handle: ?*pcap.pcap_t, // The type of this object is unclear

    pub fn create_handle(device_name: [*c]u8) !Pcap_Handle {
        var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
        const handle = pcap.pcap_open_live(
            device_name,
            65536, // Snapshot length
            1, // Promiscuous mode enabled
            1000, // Read timeout in ms
            &errbuf,
        ) orelse {
            std.debug.print("Failed to open adapter: {s}\n", .{errbuf});
            return error.PcapOpenFailed;
        };

        return Pcap_Handle{ .device_name = device_name, .handle = handle };
    }

    pub fn close_handle(self: Pcap_Handle) void {
        pcap.pcap_close(self.handle);
    }

    pub fn send_packet(self: Pcap_Handle, packet: []u8) !void {
        if (pcap.pcap_sendpacket(self.handle, packet.ptr, @intCast(packet.len)) != 0) {
            const err_msg = pcap.pcap_geterr(self.handle);
            std.debug.print("Injection error: {s}\n", .{err_msg});
            return error.InjectionFailed;
        }
    }
};

pub fn select_network_device() !*pcap.pcap_if_t {
    var errbuf: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;

    // 1. Find all available network devices on the system
    var alldevs: ?*pcap.pcap_if_t = null;
    if (pcap.pcap_findalldevs(&alldevs, &errbuf) == -1) {
        std.debug.print("Error finding devices: {s}\n", .{errbuf});
        return error.PcapFindFailed;
    }
    defer pcap.pcap_freealldevs(alldevs);

    if (alldevs == null) {
        std.debug.print("No network interfaces found.\n", .{});
        return error.NoInterfaces;
    }

    std.debug.print("--- List the Network Interfaces\n", .{});
    var current = alldevs;
    var count: usize = 0;

    while (current) |dev| : (current = dev.next) {
        // Npcap descriptions can sometimes be null, fall back to the raw name
        const description = if (dev.description) |desc|
            std.mem.span(desc)
        else
            "No description available";

        std.debug.print("[{d}] Name: {s}\n    Description: {s}\n\n", .{ count, dev.name, description });
        count += 1;
    }

    // --- USER INTERFACE SELECTION ---
    const stdin = std.io.getStdIn().reader();
    var buf: [16]u8 = undefined;

    std.debug.print("Select interface number (0-{d}): ", .{count - 1});

    // Read the line from stdin
    const line = (try stdin.readUntilDelimiterOrEof(&buf, '\n')) orelse return error.NoInput;
    // Trim carriage returns (\r) which are common on Windows line endings
    const trimmed = std.mem.trimRight(u8, line, "\r");

    // Parse the input string into an integer
    const selection = std.fmt.parseInt(usize, trimmed, 10) catch {
        std.debug.print("Invalid number format.\n", .{});
        return error.InvalidSelection;
    };

    if (selection >= count) {
        std.debug.print("Selection out of bounds.\n", .{});
        return error.SelectionOutOfBounds;
    }

    // --- NAVIGATE TO SELECTED DEVICE ---
    var selected_device = alldevs.?;
    var i: usize = 0;
    while (i < selection) : (i += 1) {
        selected_device = selected_device.next.?;
    }

    return selected_device;
}

pub fn run() !void {
    const selected_device = try select_network_device();
    std.debug.print("Opening device: {s}\n", .{selected_device.name});

    // 2. Open the selected interface in live injection mode
    const handle = try Pcap_Handle.create_handle(selected_device.name);

    defer handle.close_handle();

    const request_ip = Networking.IP_Address{ .address = .{ 192, 168, 1, 1 } };
    var full_arp_msg = try Layer2.ARP_Full_Packet.create_arp_packet(request_ip);

    var buff: [@sizeOf(Layer2.ARP_Full_Packet)]u8 = undefined;
    try full_arp_msg.to_network(&buff);
    for (buff) |byte| {
        std.debug.print("{X} ", .{byte});
    }

    std.debug.print("\n", .{});
    try handle.send_packet(buff[0..]);

    std.debug.print("Successfully injected raw ARP frame on Windows via Npcap!\n", .{});
}
