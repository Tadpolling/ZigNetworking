// Relevant structs and function to parsing pcap files
const std = @import("std");

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
