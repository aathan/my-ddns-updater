//Translation of go version done by Cursor AI. Not verified

const std = @import("std");
const net = std.net;
const http = std.http;
const json = std.json;
const time = std.time;
const fs = std.fs;
const mem = std.mem;
const os = std.os;
const log = std.log;
const heap = std.heap;

const ipCheckURL = "http://192.168.98.1/RST_st_dhcp.htm";
const ipLoginURL = "http://192.168.98.1";
const nameComAPIURL = "https://api.name.com/v4";
const nameComUsername = "aathan";
const httpTimeout = 10 * time.second;

const Record = struct {
    id: i32,
    type: []const u8,
    host: []const u8,
    answer: []const u8,
};

const ListRecordsResponse = struct {
    records: []Record,
};

const Config = struct {
    nameComToken: []const u8,
    getIPPassword: []const u8,
    getIPUsername: []const u8,
    disableUPnP: bool,
    host: []const u8,
    domain: []const u8,
    checkInterval: []const u8,
    updateInterval: []const u8,
    ignoreDNSInterval: []const u8,
};

var config: Config = undefined;
var fqdn: []const u8 = undefined;
var gpa: std.heap.GeneralPurposeAllocator = undefined;

pub fn main() !void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();
    gpa = general_purpose_allocator.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    var configPath: []const u8 = "config.json";
    var disableUPnP: bool = false;
    var checkInterval: ?time.Duration = null;
    var updateInterval: ?time.Duration = null;
    var ignoreDNSInterval: ?time.Duration = null;

    // Parse command line arguments
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (mem.eql(u8, args[i], "--config")) {
            i += 1;
            if (i < args.len) configPath = args[i];
        } else if (mem.eql(u8, args[i], "--disable-upnp")) {
            disableUPnP = true;
        } else if (mem.eql(u8, args[i], "--check-interval")) {
            i += 1;
            if (i < args.len) checkInterval = try std.fmt.parseUnsigned(u64, args[i], 10) * time.second;
        } else if (mem.eql(u8, args[i], "--update-interval")) {
            i += 1;
            if (i < args.len) updateInterval = try std.fmt.parseUnsigned(u64, args[i], 10) * time.second;
        } else if (mem.eql(u8, args[i], "--ignore-dns-interval")) {
            i += 1;
            if (i < args.len) ignoreDNSInterval = try std.fmt.parseUnsigned(u64, args[i], 10) * time.second;
        }
    }

    try loadConfig(configPath);

    // Override config settings if command-line flags are set
    if (disableUPnP) {
        config.disableUPnP = true;
    }
    if (checkInterval) |interval| {
        config.checkInterval = try std.fmt.allocPrint(gpa, "{d}", .{interval});
    }
    if (updateInterval) |interval| {
        config.updateInterval = try std.fmt.allocPrint(gpa, "{d}", .{interval});
    }
    if (ignoreDNSInterval) |interval| {
        config.ignoreDNSInterval = try std.fmt.allocPrint(gpa, "{d}", .{interval});
    }

    // Set fqdn after loading config
    fqdn = try std.fmt.allocPrint(gpa, "{s}.{s}", .{ config.host, config.domain });

    const checkIntervalDuration = try time.parse(config.checkInterval);
    const updateIntervalDuration = try time.parse(config.updateInterval);
    const ignoreDNSIntervalDuration = try time.parse(config.ignoreDNSInterval);

    var now = time.timestamp();
    var lastUpdateTime = now - @as(i64, @intCast(updateIntervalDuration));
    var lastIgnoreDNSTime = lastUpdateTime;

    var client = try http.Client.init(gpa);
    defer client.deinit();

    var firstRun = true;
    while (true) {
        if (!firstRun) {
            time.sleep(checkIntervalDuration);
        }
        firstRun = false;

        const currentIP = try getCurrentIP(&client);
        log.info("Detected current IP: {s}", .{currentIP});

        var dnsIP: ?[]const u8 = null;
        now = time.timestamp();
        if (now - lastIgnoreDNSTime <= ignoreDNSIntervalDuration) {
            dnsIP = try queryDNS();
        } else {
            lastIgnoreDNSTime = now;
        }

        if (dnsIP) |ip| {
            if (mem.eql(u8, currentIP, ip)) {
                log.info("Detected IP matches DNS IP: {s}", .{ip});
                continue;
            } else {
                log.info("Detected IP does not match DNS IP: {s}, fetching API record", .{ip});
            }
        }

        const dnsRecord = try fetchAPIRecord();

        const priorIP = dnsRecord.answer;
        if (!mem.eql(u8, currentIP, priorIP)) {
            if (now - lastUpdateTime >= updateIntervalDuration) {
                try updateAPIRecord(currentIP, dnsRecord.id);
                log.info("API record updated. Prior IP: {s}, New IP: {s}", .{ priorIP, currentIP });
                lastUpdateTime = now;
            } else {
                log.info("IP change detected, but waiting for update interval. Current IP: {s}, DNS IP: {s}", .{ currentIP, dnsRecord.answer });
            }
        } else {
            log.info("IP unchanged: {s}", .{currentIP});
        }
    }
}

fn loadConfig(path: []const u8) !void {
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(gpa, 1024 * 1024);
    defer gpa.free(content);

    var stream = json.TokenStream.init(content);
    config = try json.parse(Config, &stream, .{});
}

fn getCurrentIP(client: *http.Client) ![]const u8 {
    if (!config.disableUPnP) {
        if (try getPublicIPUPnP()) |ip| {
            return ip;
        }
        log.warn("UPnP failed, falling back to web-based IP detection", .{});
    }

    var req = try client.request(.GET, try std.Uri.parse(ipCheckURL), .{ .allocator = gpa });
    defer req.deinit();

    try req.start();
    try req.wait();

    if (req.response.status != .ok) {
        return error.HttpRequestFailed;
    }

    const body = try req.reader().readAllAlloc(gpa, 1024 * 1024);
    defer gpa.free(body);

    // Parse the HTML response to find the IP address
    // This is a simplified version and might need adjustment based on the actual HTML structure
    const ipRegex = try std.regex.Regex.compile(gpa, "\\d+\\.\\d+\\.\\d+\\.\\d+");
    defer ipRegex.deinit();

    var matches = ipRegex.match(body);
    if (matches.len == 0) {
        return error.IPNotFound;
    }

    return matches[0].slice(body);
}

fn queryDNS() ![]const u8 {
    var buf: [512]u8 = undefined;
    const result = try os.getaddrinfo(fqdn, null, null);
    defer os.freeaddrinfo(result);

    if (result.addr.family != os.AF.INET) {
        return error.NotIPv4Address;
    }

    const ip = try std.fmt.bufPrint(&buf, "{}", .{result.addr});
    return gpa.dupe(u8, ip);
}

fn fetchAPIRecord() !Record {
    var url_buf: [256]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/domains/{s}/records", .{ nameComAPIURL, config.domain });

    var req = try http.Client.request(.GET, try std.Uri.parse(url), .{ .allocator = gpa });
    defer req.deinit();

    req.headers.append("Authorization", try std.fmt.allocPrint(gpa, "Basic {s}", .{std.base64.standard.Encoder.encode(gpa, try std.fmt.allocPrint(gpa, "{s}:{s}", .{ nameComUsername, config.nameComToken }))})) catch unreachable;

    try req.start();
    try req.wait();

    if (req.response.status != .ok) {
        return error.ApiRequestFailed;
    }

    const body = try req.reader().readAllAlloc(gpa, 1024 * 1024);
    defer gpa.free(body);

    var stream = json.TokenStream.init(body);
    const response = try json.parse(ListRecordsResponse, &stream, .{});

    for (response.records) |record| {
        if (mem.eql(u8, record.host, config.host)) {
            return record;
        }
    }

    return error.RecordNotFound;
}

fn updateAPIRecord(newIP: []const u8, recordID: i32) !void {
    var url_buf: [256]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/domains/{s}/records/{d}", .{ nameComAPIURL, config.domain, recordID });

    const payload = try std.json.stringify(.{
        .host = config.host,
        .type = "A",
        .answer = newIP,
        .ttl = 300,
    }, .{}, gpa);
    defer gpa.free(payload);

    var req = try http.Client.request(.PUT, try std.Uri.parse(url), .{ .allocator = gpa });
    defer req.deinit();

    req.headers.append("Authorization", try std.fmt.allocPrint(gpa, "Basic {s}", .{std.base64.standard.Encoder.encode(gpa, try std.fmt.allocPrint(gpa, "{s}:{s}", .{ nameComUsername, config.nameComToken }))})) catch unreachable;
    req.headers.append("Content-Type", "application/json") catch unreachable;

    try req.start();
    try req.writer().writeAll(payload);
    try req.finish();
    try req.wait();

    if (req.response.status != .ok) {
        return error.ApiRequestFailed;
    }
}

fn getPublicIPUPnP() !?[]const u8 {
    // Note: UPnP implementation is not provided in this Zig translation
    // as it would require a Zig-specific UPnP library or implementation
    return null;
}
