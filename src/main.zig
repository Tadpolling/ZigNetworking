const std = @import("std");
const Pcap = @import("./pcap.zig");
const Networking = @import("./networking.zig");
const Layer2 = @import("./layer2.zig");

pub fn main() !void {
    // try Pcap.run();
    const raw_array = [_]u8{ 0x04, 0x00, 0x04, 0x96, 0x1f, 0xa7, 0x26 };
    const array = raw_array[0..];
    const tlv = try Layer2.TLV.create_TLV(0x0207, array);
    tlv.print();
}
