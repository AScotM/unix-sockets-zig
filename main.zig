const std = @import("std");
const Allocator = std.mem.Allocator;

extern "c" fn fopen([*:0]const u8, [*:0]const u8) ?*anyopaque;
extern "c" fn fclose(*anyopaque) c_int;
extern "c" fn fgets([*]u8, c_int, *anyopaque) ?[*]u8;
extern "c" fn fread([*]u8, usize, usize, *anyopaque) usize;
extern "c" fn opendir([*:0]const u8) ?*anyopaque;
extern "c" fn readdir(*anyopaque) ?*Dirent;
extern "c" fn closedir(*anyopaque) c_int;
extern "c" fn readlink([*:0]const u8, [*]u8, usize) isize;
extern "c" fn printf([*:0]const u8, ...) c_int;
extern "c" fn putchar(c_int) c_int;

const Dirent = extern struct {
    ino: u64,
    off: i64,
    reclen: u16,
    kind: u8,
    name: [256]u8,
};

const SocketType = enum(u16) {
    stream = 1,
    datagram = 2,
    seqpacket = 5,
    _,
};

const SocketState = enum(u8) {
    free = 0,
    unconnected = 1,
    connecting = 2,
    connected = 3,
    disconnecting = 4,
    _,
};

const SortKey = enum { inode, pid, kind, state, path, owners };

const Owner = struct {
    pid: i32,
    fd: u32,
    process: []const u8,
};

const Socket = struct {
    inode: u64,
    references: u64,
    protocol: u16,
    flags: u32,
    kind: SocketType,
    state: SocketState,
    path: []const u8,
    owners: std.ArrayList(Owner) = .empty,

    fn listening(self: Socket) bool {
        return (self.flags & 0x10000) != 0;
    }

    fn abstract(self: Socket) bool {
        return std.mem.startsWith(u8, self.path, "@");
    }

    fn primaryPid(self: Socket) i32 {
        return if (self.owners.items.len == 0) -1 else self.owners.items[0].pid;
    }
};

const Config = struct {
    json: bool = false,
    summary: bool = false,
    show_all: bool = false,
    owners: bool = false,
    processes: bool = false,
    diagnostics: bool = false,
    pid: ?i32 = null,
    kind: ?SocketType = null,
    state: ?SocketState = null,
    path_filter: ?[]const u8 = null,
    sort: SortKey = .inode,
    descending: bool = false,
};

const Diagnostics = struct {
    lines: usize = 0,
    malformed: usize = 0,
    processes_seen: usize = 0,
    processes_unreadable: usize = 0,
    descriptors_seen: usize = 0,
    descriptors_unreadable: usize = 0,
    socket_links: usize = 0,
    matched_links: usize = 0,
};

const Stats = struct {
    total: usize = 0,
    streams: usize = 0,
    datagrams: usize = 0,
    seqpackets: usize = 0,
    other: usize = 0,
    listening: usize = 0,
    connected: usize = 0,
    named: usize = 0,
    anonymous: usize = 0,
    abstract: usize = 0,
    owned: usize = 0,
    owner_links: usize = 0,
};

const ProcessStat = struct {
    pid: i32,
    name: []const u8,
    sockets: usize = 0,
    descriptors: usize = 0,
};

const Scanner = struct {
    allocator: Allocator,
    sockets: std.ArrayList(Socket) = .empty,
    inode_map: std.AutoHashMap(u64, usize),
    diagnostics: Diagnostics = .{},

    fn init(allocator: Allocator) Scanner {
        return .{ .allocator = allocator, .inode_map = std.AutoHashMap(u64, usize).init(allocator) };
    }

    fn deinit(self: *Scanner) void {
        for (self.sockets.items) |*socket| {
            self.allocator.free(socket.path);
            socket.owners.deinit(self.allocator);
        }
        self.sockets.deinit(self.allocator);
        self.inode_map.deinit();
    }

    fn collect(self: *Scanner) !void {
        try self.collectSockets();
        try self.collectProcesses();
    }

    fn collectSockets(self: *Scanner) !void {
        const file = fopen("/proc/net/unix", "r") orelse return error.CannotOpenUnixSocketTable;
        defer _ = fclose(file);
        var buffer: [131072]u8 = undefined;
        _ = fgets(&buffer, @intCast(buffer.len), file);
        while (fgets(&buffer, @intCast(buffer.len), file) != null) {
            self.diagnostics.lines += 1;
            const line = std.mem.sliceTo(&buffer, 0);
            if (line.len == buffer.len - 1 and line[line.len - 1] != '\n') {
                self.diagnostics.malformed += 1;
                continue;
            }
            const socket = try self.parseSocket(line) orelse {
                self.diagnostics.malformed += 1;
                continue;
            };
            const index = self.sockets.items.len;
            try self.sockets.append(self.allocator, socket);
            if (socket.inode != 0) try self.inode_map.put(socket.inode, index);
        }
    }

    fn parseSocket(self: *Scanner, line: []const u8) !?Socket {
        var fields: [7][]const u8 = undefined;
        var position: usize = 0;
        for (&fields) |*field| {
            while (position < line.len and std.ascii.isWhitespace(line[position])) : (position += 1) {}
            if (position == line.len) return null;
            const start = position;
            while (position < line.len and !std.ascii.isWhitespace(line[position])) : (position += 1) {}
            field.* = line[start..position];
        }
        while (position < line.len and std.ascii.isWhitespace(line[position])) : (position += 1) {}
        const references = std.fmt.parseInt(u64, fields[1], 16) catch return null;
        const protocol = std.fmt.parseInt(u16, fields[2], 16) catch return null;
        const flags = std.fmt.parseInt(u32, fields[3], 16) catch return null;
        const kind = std.fmt.parseInt(u16, fields[4], 16) catch return null;
        const state = std.fmt.parseInt(u8, fields[5], 16) catch return null;
        const inode = std.fmt.parseInt(u64, fields[6], 10) catch return null;
        const path = std.mem.trimEnd(u8, line[position..], "\r\n");
        return .{
            .inode = inode,
            .references = references,
            .protocol = protocol,
            .flags = flags,
            .kind = @enumFromInt(kind),
            .state = @enumFromInt(state),
            .path = try self.allocator.dupe(u8, path),
        };
    }

    fn collectProcesses(self: *Scanner) !void {
        const directory = opendir("/proc") orelse return error.CannotOpenProc;
        defer _ = closedir(directory);
        while (readdir(directory)) |entry| {
            const name = std.mem.sliceTo(&entry.name, 0);
            const pid = std.fmt.parseInt(i32, name, 10) catch continue;
            if (pid <= 0) continue;
            self.diagnostics.processes_seen += 1;
            try self.inspectProcess(pid);
        }
    }

    fn inspectProcess(self: *Scanner, pid: i32) !void {
        var path_buffer: [128]u8 = undefined;
        const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/fd", .{pid}) catch return;
        const directory = opendir(path.ptr) orelse {
            self.diagnostics.processes_unreadable += 1;
            return;
        };
        defer _ = closedir(directory);
        var process_name: ?[]const u8 = null;
        defer if (process_name) |name| self.allocator.free(name);
        while (readdir(directory)) |entry| {
            const fd_name = std.mem.sliceTo(&entry.name, 0);
            const fd = std.fmt.parseInt(u32, fd_name, 10) catch continue;
            self.diagnostics.descriptors_seen += 1;
            var link_buffer: [160]u8 = undefined;
            const link_path = std.fmt.bufPrintZ(&link_buffer, "/proc/{d}/fd/{s}", .{ pid, fd_name }) catch continue;
            var target: [1024]u8 = undefined;
            const length = readlink(link_path.ptr, &target, target.len);
            if (length < 0) {
                self.diagnostics.descriptors_unreadable += 1;
                continue;
            }
            if (length == 0 or @as(usize, @intCast(length)) == target.len) continue;
            const link = target[0..@intCast(length)];
            if (!std.mem.startsWith(u8, link, "socket:[") or !std.mem.endsWith(u8, link, "]")) continue;
            self.diagnostics.socket_links += 1;
            const inode = std.fmt.parseInt(u64, link[8 .. link.len - 1], 10) catch continue;
            const index = self.inode_map.get(inode) orelse continue;
            if (process_name == null) process_name = try self.readProcessName(pid);
            try self.sockets.items[index].owners.append(self.allocator, .{
                .pid = pid,
                .fd = fd,
                .process = try self.allocator.dupe(u8, process_name.?),
            });
            self.diagnostics.matched_links += 1;
        }
    }

    fn readProcessName(self: *Scanner, pid: i32) ![]const u8 {
        var path_buffer: [128]u8 = undefined;
        const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/comm", .{pid}) catch return self.allocator.dupe(u8, "");
        const file = fopen(path.ptr, "r") orelse return self.allocator.dupe(u8, "");
        defer _ = fclose(file);
        var buffer: [4096]u8 = undefined;
        if (fgets(&buffer, @intCast(buffer.len), file) == null) return self.allocator.dupe(u8, "");
        return self.allocator.dupe(u8, std.mem.trim(u8, std.mem.sliceTo(&buffer, 0), "\r\n"));
    }
};

fn typeName(kind: SocketType) []const u8 {
    return switch (kind) { .stream => "STREAM", .datagram => "DGRAM", .seqpacket => "SEQPACKET", _ => "OTHER" };
}

fn stateName(state: SocketState) []const u8 {
    return switch (state) {
        .free => "FREE", .unconnected => "UNCONNECTED", .connecting => "CONNECTING",
        .connected => "CONNECTED", .disconnecting => "DISCONNECTING", _ => "UNKNOWN",
    };
}

fn matches(socket: Socket, config: Config) bool {
    if (!config.show_all and socket.inode == 0) return false;
    if (config.pid) |pid| {
        var found = false;
        for (socket.owners.items) |owner| {
            if (owner.pid == pid) { found = true; break; }
        }
        if (!found) return false;
    }
    if (config.kind) |kind| { if (socket.kind != kind) return false; }
    if (config.state) |state| { if (socket.state != state) return false; }
    if (config.path_filter) |filter| {
        if (std.mem.indexOf(u8, socket.path, filter) == null) return false;
    }
    return true;
}

fn calculateStats(sockets: []const Socket, config: Config) Stats {
    var stats = Stats{};
    for (sockets) |socket| {
        if (!matches(socket, config)) continue;
        stats.total += 1;
        switch (socket.kind) {
            .stream => stats.streams += 1, .datagram => stats.datagrams += 1,
            .seqpacket => stats.seqpackets += 1, _ => stats.other += 1,
        }
        if (socket.listening()) stats.listening += 1;
        if (socket.state == .connected) stats.connected += 1;
        if (socket.path.len > 0) stats.named += 1 else stats.anonymous += 1;
        if (socket.abstract()) stats.abstract += 1;
        if (socket.owners.items.len > 0) stats.owned += 1;
        stats.owner_links += socket.owners.items.len;
    }
    return stats;
}

fn lessThan(config: Config, a: Socket, b: Socket) bool {
    const order: std.math.Order = switch (config.sort) {
        .inode => std.math.order(a.inode, b.inode),
        .pid => std.math.order(a.primaryPid(), b.primaryPid()),
        .kind => std.math.order(@intFromEnum(a.kind), @intFromEnum(b.kind)),
        .state => std.math.order(@intFromEnum(a.state), @intFromEnum(b.state)),
        .path => std.mem.order(u8, a.path, b.path),
        .owners => std.math.order(a.owners.items.len, b.owners.items.len),
    };
    return if (config.descending) order == .gt else order == .lt;
}

fn jsonString(value: []const u8) void {
    _ = putchar('"');
    for (value) |byte| {
        switch (byte) {
            '"' => _ = printf("\\\""),
            '\\' => _ = printf("\\\\"),
            '\n' => _ = printf("\\n"),
            '\r' => _ = printf("\\r"),
            '\t' => _ = printf("\\t"),
            else => {
                if (byte < 0x20 or byte >= 0x7f) {
                    _ = printf("\\u%04x", @as(c_uint, byte));
                } else {
                    _ = putchar(@as(c_int, byte));
                }
            },
        }
    }
    _ = putchar('"');
}

fn printSafe(value: []const u8) void {
    for (value) |byte| {
        if (byte >= 0x20 and byte < 0x7f) {
            _ = putchar(@as(c_int, byte));
        } else {
            _ = printf("\\x%02x", @as(c_uint, byte));
        }
    }
}

fn printStats(stats: Stats, json: bool) void {
    if (json) {
        _ = printf("\"statistics\":{\"total\":%zu,\"stream\":%zu,\"datagram\":%zu,\"seqpacket\":%zu,\"other\":%zu,\"listening\":%zu,\"connected\":%zu,\"named\":%zu,\"anonymous\":%zu,\"abstract\":%zu,\"pid_mapped\":%zu,\"owner_descriptors\":%zu}", stats.total, stats.streams, stats.datagrams, stats.seqpackets, stats.other, stats.listening, stats.connected, stats.named, stats.anonymous, stats.abstract, stats.owned, stats.owner_links);
    } else {
        _ = printf("\nSocket statistics\n-----------------\nTotal:              %zu\nStream:             %zu\nDatagram:           %zu\nSeqpacket:          %zu\nOther:              %zu\nListening:          %zu\nConnected:          %zu\nNamed:              %zu\nAnonymous:          %zu\nAbstract:           %zu\nPID mapped:         %zu\nOwner descriptors:  %zu\n", stats.total, stats.streams, stats.datagrams, stats.seqpackets, stats.other, stats.listening, stats.connected, stats.named, stats.anonymous, stats.abstract, stats.owned, stats.owner_links);
    }
}

fn printDiagnostics(d: Diagnostics, json: bool) void {
    if (json) {
        _ = printf("\"diagnostics\":{\"lines\":%zu,\"malformed\":%zu,\"processes_seen\":%zu,\"processes_unreadable\":%zu,\"descriptors_seen\":%zu,\"descriptors_unreadable\":%zu,\"socket_links\":%zu,\"matched_links\":%zu}", d.lines, d.malformed, d.processes_seen, d.processes_unreadable, d.descriptors_seen, d.descriptors_unreadable, d.socket_links, d.matched_links);
    } else {
        _ = printf("\nCollection diagnostics\n----------------------\nSocket lines:       %zu\nMalformed lines:    %zu\nProcesses scanned:  %zu\nProcesses skipped:  %zu\nDescriptors seen:   %zu\nDescriptors errors: %zu\nSocket links:       %zu\nMatched links:      %zu\n", d.lines, d.malformed, d.processes_seen, d.processes_unreadable, d.descriptors_seen, d.descriptors_unreadable, d.socket_links, d.matched_links);
    }
}

fn collectProcessStats(allocator: Allocator, sockets: []const Socket, config: Config) !std.ArrayList(ProcessStat) {
    var result: std.ArrayList(ProcessStat) = .empty;
    var indices = std.AutoHashMap(i32, usize).init(allocator);
    defer indices.deinit();
    for (sockets) |socket| {
        if (!matches(socket, config)) continue;
        for (socket.owners.items) |owner| {
            const index = indices.get(owner.pid) orelse blk: {
                const next = result.items.len;
                try result.append(allocator, .{ .pid = owner.pid, .name = owner.process });
                try indices.put(owner.pid, next);
                break :blk next;
            };
            result.items[index].descriptors += 1;
            var first = true;
            for (socket.owners.items) |previous| {
                if (previous.pid == owner.pid and previous.fd != owner.fd) {
                    if (previous.fd < owner.fd) { first = false; break; }
                }
            }
            if (first) result.items[index].sockets += 1;
        }
    }
    return result;
}

fn printProcesses(processes: []const ProcessStat, json: bool) void {
    if (json) {
        _ = printf("\"processes\":[");
        for (processes, 0..) |process, i| {
            if (i != 0) _ = printf(",");
            _ = printf("{\"pid\":%d,\"name\":", @as(c_int, process.pid));
            jsonString(process.name);
            _ = printf(",\"sockets\":%zu,\"descriptors\":%zu}", process.sockets, process.descriptors);
        }
        _ = printf("]");
    } else {
        _ = printf("\nProcess statistics\n------------------\n%-10s %-12s %-12s %s\n", "PID", "SOCKETS", "DESCRIPTORS", "NAME");
        for (processes) |process| {
            _ = printf("%-10d %-12zu %-12zu ", @as(c_int, process.pid), process.sockets, process.descriptors);
            printSafe(process.name);
            _ = printf("\n");
        }
    }
}

fn printText(scanner: *const Scanner, config: Config, processes: []const ProcessStat) void {
    const stats = calculateStats(scanner.sockets.items, config);
    _ = printf("Unix Domain Socket Inspector\n============================\n");
    if (!config.summary) {
        _ = printf("\n%-12s %-8s %-10s %-15s %-10s %-8s %s\n", "INODE", "PID", "TYPE", "STATE", "FLAGS", "OWNERS", "PATH");
        for (scanner.sockets.items) |socket| {
            if (!matches(socket, config)) continue;
            const kind = typeName(socket.kind);
            const state = stateName(socket.state);
            _ = printf("%-12llu %-8d %-10.*s %-15.*s 0x%08x %-8zu ", @as(c_ulonglong, socket.inode), @as(c_int, socket.primaryPid()), @as(c_int, @intCast(kind.len)), kind.ptr, @as(c_int, @intCast(state.len)), state.ptr, @as(c_uint, socket.flags), socket.owners.items.len);
            if (socket.path.len == 0) _ = printf("-") else printSafe(socket.path);
            _ = printf("\n");
            if (config.owners) {
                for (socket.owners.items) |owner| {
                    _ = printf("    PID=%d FD=%u PROCESS=", @as(c_int, owner.pid), @as(c_uint, owner.fd));
                    printSafe(owner.process);
                    _ = printf("\n");
                }
            }
        }
    }
    printStats(stats, false);
    if (config.processes) printProcesses(processes, false);
    if (config.diagnostics) printDiagnostics(scanner.diagnostics, false);
}

fn printJson(scanner: *const Scanner, config: Config, processes: []const ProcessStat) void {
    const stats = calculateStats(scanner.sockets.items, config);
    _ = printf("{\"sockets\":[");
    var first = true;
    if (!config.summary) {
        for (scanner.sockets.items) |socket| {
            if (!matches(socket, config)) continue;
            if (!first) _ = printf(",");
            first = false;
            _ = printf("{\"inode\":%llu,\"pid\":", @as(c_ulonglong, socket.inode));
            if (socket.owners.items.len == 0) _ = printf("null") else _ = printf("%d", @as(c_int, socket.primaryPid()));
            _ = printf(",\"type\":");
            jsonString(typeName(socket.kind));
            _ = printf(",\"state\":");
            jsonString(stateName(socket.state));
            _ = printf(",\"flags\":%u,\"references\":%llu,\"protocol\":%u,\"path\":", @as(c_uint, socket.flags), @as(c_ulonglong, socket.references), @as(c_uint, socket.protocol));
            jsonString(socket.path);
            _ = printf(",\"listening\":%s,\"abstract\":%s,\"owners\":[", if (socket.listening()) @as([*:0]const u8, "true") else @as([*:0]const u8, "false"), if (socket.abstract()) @as([*:0]const u8, "true") else @as([*:0]const u8, "false"));
            for (socket.owners.items, 0..) |owner, i| {
                if (i != 0) _ = printf(",");
                _ = printf("{\"pid\":%d,\"fd\":%u,\"process\":", @as(c_int, owner.pid), @as(c_uint, owner.fd));
                jsonString(owner.process);
                _ = printf("}");
            }
            _ = printf("]}");
        }
    }
    _ = printf("],");
    printStats(stats, true);
    if (config.processes) { _ = printf(","); printProcesses(processes, true); }
    if (config.diagnostics) { _ = printf(","); printDiagnostics(scanner.diagnostics, true); }
    _ = printf("}\n");
}

fn printHelp() void {
    _ = printf("unix-sockets-zig\n\nUsage: zig run main.zig -lc -- [options]\n\nOptions:\n  --json             JSON output\n  --summary          Statistics only\n  --all              Include inode-zero entries\n  --owners           Display all owner descriptors in text mode\n  --processes        Display per-process statistics\n  --diagnostics      Display collection diagnostics\n  --pid N            Filter by process ID\n  --type TYPE        stream, dgram, seqpacket\n  --state N          Filter by numeric socket state\n  --path TEXT        Filter by socket path\n  --sort KEY         inode, pid, type, state, path, owners\n  --descending       Reverse sorting order\n  --help             Display help\n");
}

fn parseArgs(allocator: Allocator) !?Config {
    const file = fopen("/proc/self/cmdline", "rb") orelse return error.CannotReadCommandLine;
    defer _ = fclose(file);
    var buffer: [65536]u8 = undefined;
    const length = fread(&buffer, 1, buffer.len, file);
    if (length == 0) return error.EmptyCommandLine;
    if (length == buffer.len) return error.CommandLineTooLong;
    var arguments: std.ArrayList([]const u8) = .empty;
    defer arguments.deinit(allocator);
    var iterator = std.mem.splitScalar(u8, buffer[0..@min(length, buffer.len)], 0);
    while (iterator.next()) |argument| {
        if (argument.len != 0) try arguments.append(allocator, argument);
    }
    const args = arguments.items;
    var config = Config{};
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--help")) { printHelp(); return null; }
        if (std.mem.eql(u8, arg, "--json")) { config.json = true; continue; }
        if (std.mem.eql(u8, arg, "--summary")) { config.summary = true; continue; }
        if (std.mem.eql(u8, arg, "--all")) { config.show_all = true; continue; }
        if (std.mem.eql(u8, arg, "--owners")) { config.owners = true; continue; }
        if (std.mem.eql(u8, arg, "--processes")) { config.processes = true; continue; }
        if (std.mem.eql(u8, arg, "--diagnostics")) { config.diagnostics = true; continue; }
        if (std.mem.eql(u8, arg, "--descending")) { config.descending = true; continue; }
        index += 1;
        if (index >= args.len) return error.MissingOptionValue;
        const value = args[index];
        if (std.mem.eql(u8, arg, "--pid")) {
            config.pid = try std.fmt.parseInt(i32, value, 10);
            if (config.pid.? <= 0) return error.InvalidPid;
        } else if (std.mem.eql(u8, arg, "--type")) {
            if (std.ascii.eqlIgnoreCase(value, "stream")) config.kind = .stream else if (std.ascii.eqlIgnoreCase(value, "dgram")) config.kind = .datagram else if (std.ascii.eqlIgnoreCase(value, "seqpacket")) config.kind = .seqpacket else return error.InvalidSocketType;
        } else if (std.mem.eql(u8, arg, "--state")) {
            config.state = @enumFromInt(try std.fmt.parseInt(u8, value, 10));
        } else if (std.mem.eql(u8, arg, "--path")) {
            config.path_filter = value;
        } else if (std.mem.eql(u8, arg, "--sort")) {
            if (std.mem.eql(u8, value, "inode")) config.sort = .inode else if (std.mem.eql(u8, value, "pid")) config.sort = .pid else if (std.mem.eql(u8, value, "type")) config.sort = .kind else if (std.mem.eql(u8, value, "state")) config.sort = .state else if (std.mem.eql(u8, value, "path")) config.sort = .path else if (std.mem.eql(u8, value, "owners")) config.sort = .owners else return error.InvalidSortKey;
        } else return error.UnknownArgument;
    }
    return config;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const config = (try parseArgs(allocator)) orelse return;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();
    try scanner.collect();
    std.sort.heap(Socket, scanner.sockets.items, config, lessThan);
    var processes = try collectProcessStats(allocator, scanner.sockets.items, config);
    defer processes.deinit(allocator);
    if (config.json) printJson(&scanner, config, processes.items) else printText(&scanner, config, processes.items);
}
