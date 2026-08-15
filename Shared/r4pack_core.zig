pub const max_r4x_bytes: usize = 8 * 1024;
/// In-Guest-Grenze fuer den Ressourcenbereich eines gepackten Moduls.
pub const max_rsrc_bytes: usize = 16 * 1024;

const R4M_HEADER_SIZE: usize = 64;
const R4M_SECTION_SIZE: usize = 32;
const R4M_ENTRY_SIZE: usize = 16;
const R4M_IMPORT_SIZE: usize = 16;
const R4M_EXPORT_SIZE: usize = 16;
const R4M_VERSION: u16 = 1;
const ARCH_X86_64: u16 = 1;
const MODULE_KIND_R4X: u16 = 1;
const ENTRY_KIND_R4X: u32 = 1;
const R4X_FLAG_APP_CLASS_CONSOLE: u32 = 0x00000001;
const R4X_FLAG_APP_CLASS_GUI: u32 = 0x00000002;
const R4M_SECTION_FLAG_ALLOC: u32 = 0x00000001;
const R4M_SECTION_FLAG_EXEC: u32 = 0x00000002;
// Ressourcenbereich nach Contract/ABI/R4M0.txt. Der Host-Erzeuger ist
// R4XBuilder; dieses Layout muss fuer gleiche Eingaben BYTEGLEICH bleiben -
// der Vertrag laesst dafuer keinen Freiheitsgrad.
const RSRC_ENTRY_SIZE: usize = 16;
const RSRC_MAX_ENTRIES: usize = 64;
pub const RSRC_TYPE_ICON: u16 = 1;
pub const RSRC_TYPE_HELP: u16 = 2;
pub const RSRC_TYPE_FILE: u16 = 3;

pub const PackResult = struct {
    ok: bool,
    bytes: []const u8 = "",
    err: []const u8 = "",
};

/// Eine einzubettende Ressource in Vertragsreihenfolge (erst Icons, dann
/// hoechstens ein Help, dann benannte Dateien).
pub const Resource = struct {
    typ: u16,
    /// Nur fuer RSRC_TYPE_FILE.
    name: []const u8 = "",
    bytes: []const u8,
};

const ImportSet = enum {
    console,
    desktop_ok,
};

pub fn packConsoleR4X(module_name: []const u8, code: []const u8, resources: []const Resource, out: []u8) PackResult {
    return packR4X(module_name, code, resources, out, R4X_FLAG_APP_CLASS_CONSOLE, "r4x.class=console", .console);
}

pub fn packDesktopOkR4X(module_name: []const u8, code: []const u8, resources: []const Resource, out: []u8) PackResult {
    return packR4X(module_name, code, resources, out, R4X_FLAG_APP_CLASS_GUI, "r4x.class=gui", .desktop_ok);
}

fn packR4X(module_name: []const u8, code: []const u8, resources: []const Resource, out: []u8, app_class_flag: u32, app_class_meta: []const u8, import_set: ImportSet) PackResult {
    if (module_name.len == 0) return fail("missing module name");
    if (code.len == 0) return fail("missing code");
    if (validateResources(resources)) |message| return fail(message);
    const rsrc_len = resourceSectionLength(resources);
    if (rsrc_len > max_rsrc_bytes) return fail("resource area exceeds in-guest limit");

    const has_rsrc = resources.len != 0;
    const section_count: usize = if (has_rsrc) 2 else 1;
    const entry_count: usize = 1;
    const import_count = importCount(import_set);
    const export_count: usize = 1;

    const section_off = R4M_HEADER_SIZE;
    const entry_off = section_off + section_count * R4M_SECTION_SIZE;
    const import_off = entry_off + entry_count * R4M_ENTRY_SIZE;
    const export_off = import_off + import_count * R4M_IMPORT_SIZE;
    const code_off = alignForward(export_off + export_count * R4M_EXPORT_SIZE, 16);
    const rsrc_off = if (has_rsrc) alignForward(code_off + code.len, 16) else code_off + code.len;
    const string_off = rsrc_off + rsrc_len;

    var string_len: usize = 0;
    string_len += module_name.len + 1;
    var import_index: usize = 0;
    while (import_index < import_count) : (import_index += 1) {
        string_len += importModule(import_set, import_index).len + 1;
        string_len += importSymbol(import_set, import_index).len + 1;
    }
    string_len += "R4XStart".len + 1;
    string_len += app_class_meta.len + 1;
    string_len += "r4x.start=r4xstart".len + 1;
    string_len += "r4x.entry=R4XStart".len + 1;
    string_len += "r4x.start_abi=1".len + 1;
    string_len += "r4x.context=R4XStartContext".len + 1;
    string_len += "generated_by=R4CC-r4mf-v2".len + 1;

    const total_len = string_off + string_len;
    if (total_len > out.len) return fail("R4X image buffer too small");
    const image = out[0..total_len];
    @memset(image, 0);

    @memcpy(image[code_off .. code_off + code.len], code);
    if (has_rsrc) writeResourceSection(image[rsrc_off .. rsrc_off + rsrc_len], resources);

    var strings = string_off;
    const module_name_off: u32 = @intCast(putZ(image, &strings, module_name));
    _ = module_name_off;
    var import_module_offs: [3]u32 = undefined;
    var import_symbol_offs: [3]u32 = undefined;
    if (import_count > import_module_offs.len) return fail("too many imports");
    import_index = 0;
    while (import_index < import_count) : (import_index += 1) {
        import_module_offs[import_index] = @intCast(putZ(image, &strings, importModule(import_set, import_index)));
        import_symbol_offs[import_index] = @intCast(putZ(image, &strings, importSymbol(import_set, import_index)));
    }
    const export_name_off: u32 = @intCast(putZ(image, &strings, "R4XStart"));
    _ = putZ(image, &strings, app_class_meta);
    _ = putZ(image, &strings, "r4x.start=r4xstart");
    _ = putZ(image, &strings, "r4x.entry=R4XStart");
    _ = putZ(image, &strings, "r4x.start_abi=1");
    _ = putZ(image, &strings, "r4x.context=R4XStartContext");
    _ = putZ(image, &strings, "generated_by=R4CC-r4mf-v2");

    @memcpy(image[0..4], "R4M0");
    wU16(image, 4, R4M_VERSION);
    wU16(image, 6, ARCH_X86_64);
    wU16(image, 8, MODULE_KIND_R4X);
    wU16(image, 10, R4M_HEADER_SIZE);
    wU32(image, 12, app_class_flag);
    wU32(image, 16, @intCast(section_off));
    wU32(image, 20, @intCast(section_count));
    wU32(image, 24, @intCast(import_off));
    wU32(image, 28, @intCast(import_count));
    wU32(image, 32, @intCast(export_off));
    wU32(image, 36, export_count);
    wU32(image, 40, 0);
    wU32(image, 44, 0);
    wU32(image, 48, @intCast(entry_off));
    wU32(image, 52, entry_count);
    wU32(image, 56, @intCast(string_off));
    wU32(image, 60, @intCast(string_len));

    writeSection(image, section_off, ".text", R4M_SECTION_FLAG_ALLOC | R4M_SECTION_FLAG_EXEC, @intCast(code_off), @intCast(code.len), @intCast(code.len), 16);
    if (has_rsrc) {
        writeSection(image, section_off + R4M_SECTION_SIZE, ".rsrc", 0, @intCast(rsrc_off), @intCast(rsrc_len), @intCast(rsrc_len), 16);
    }
    wU32(image, entry_off + 0, ENTRY_KIND_R4X);
    wU32(image, entry_off + 4, 0);
    wU32(image, entry_off + 8, 0);
    wU32(image, entry_off + 12, 0);

    import_index = 0;
    while (import_index < import_count) : (import_index += 1) {
        const off = import_off + import_index * R4M_IMPORT_SIZE;
        wU32(image, off + 0, import_module_offs[import_index]);
        wU32(image, off + 4, import_symbol_offs[import_index]);
        wU32(image, off + 8, importMinVersion(import_set, import_index));
        wU32(image, off + 12, importFlags(import_set, import_index));
    }

    wU32(image, export_off + 0, export_name_off);
    wU32(image, export_off + 4, 0);
    wU32(image, export_off + 8, 0);
    wU32(image, export_off + 12, 1);

    return .{ .ok = true, .bytes = image };
}

/// Validiert die Ressourcen wie der Host-Erzeuger: Vertragsreihenfolge
/// (Icons, dann hoechstens ein Help, dann Dateien), gueltige Namen,
/// eindeutig case-insensitive, keine leeren Blobs, Icons ICO-tauglich.
/// Liefert null bei Erfolg, sonst die Fehlermeldung.
fn validateResources(resources: []const Resource) ?[]const u8 {
    if (resources.len > RSRC_MAX_ENTRIES) return "too many resources";
    var seen_help = false;
    var seen_file = false;
    for (resources, 0..) |resource, index| {
        if (resource.bytes.len == 0) return "empty resource";
        switch (resource.typ) {
            RSRC_TYPE_ICON => {
                if (seen_help or seen_file) return "resource order violates contract";
                if (validateIco(resource.bytes)) |message| return message;
            },
            RSRC_TYPE_HELP => {
                if (seen_help) return "more than one helpfile";
                if (seen_file) return "resource order violates contract";
                seen_help = true;
            },
            RSRC_TYPE_FILE => {
                seen_file = true;
                if (resource.name.len == 0 or resource.name.len > 63) return "bad resource name";
                for (resource.name) |byte| {
                    if (byte < 0x21 or byte > 0x7E) return "bad resource name";
                    if (byte == '/' or byte == '\\' or byte == ':') return "bad resource name";
                }
                for (resources[0..index]) |prior| {
                    if (prior.typ == RSRC_TYPE_FILE and equalsIgnoreCase(prior.name, resource.name)) return "duplicate resource name";
                }
            },
            else => return "unknown resource type",
        }
    }
    return null;
}

/// Dieselben ICO-Grenzen wie beim Host-Erzeuger: klassischer Container,
/// kein PNG-Eintrag, mindestens ein 32x32-Eintrag in 32 oder 8 bpp.
fn validateIco(bytes: []const u8) ?[]const u8 {
    if (bytes.len < 6 or rU16(bytes, 0) != 0 or rU16(bytes, 2) != 1) return "icon is not a classic ICO container";
    const entry_count = rU16(bytes, 4);
    if (entry_count == 0) return "icon has no entries";
    var usable = false;
    var index: usize = 0;
    while (index < entry_count) : (index += 1) {
        const off = 6 + index * 16;
        if (off + 16 > bytes.len) return "icon entry outside file";
        const width: u32 = if (bytes[off] == 0) 256 else bytes[off];
        const height: u32 = if (bytes[off + 1] == 0) 256 else bytes[off + 1];
        const image_size = rU32(bytes, off + 8);
        const image_off = rU32(bytes, off + 12);
        if (@as(u64, image_off) + image_size > bytes.len) return "icon data outside file";
        if (image_size >= 8 and bytes[image_off] == 0x89 and bytes[image_off + 1] == 'P' and bytes[image_off + 2] == 'N' and bytes[image_off + 3] == 'G') {
            return "icon entry is PNG-compressed";
        }
        if (image_size >= 16 and width == 32 and height == 32) {
            const bits = rU16(bytes, @as(usize, image_off) + 14);
            if (bits == 32 or bits == 8) usable = true;
        }
    }
    if (!usable) return "icon has no usable 32x32 entry";
    return null;
}

/// Nutzbytes einer Ressource: bei Help ohne fuehrendes BOM der Bauquelle.
fn resourcePayload(resource: Resource) []const u8 {
    if (resource.typ == RSRC_TYPE_HELP and resource.bytes.len >= 3 and
        resource.bytes[0] == 0xEF and resource.bytes[1] == 0xBB and resource.bytes[2] == 0xBF)
    {
        return resource.bytes[3..];
    }
    return resource.bytes;
}

pub fn resourceSectionLength(resources: []const Resource) usize {
    if (resources.len == 0) return 0;
    var names_len: usize = 0;
    for (resources) |resource| {
        if (resource.typ == RSRC_TYPE_FILE) names_len += resource.name.len + 1;
    }
    var cursor = 4 + resources.len * RSRC_ENTRY_SIZE + names_len;
    for (resources) |resource| {
        cursor = alignForward(cursor, 16);
        cursor += resourcePayload(resource).len;
    }
    return cursor;
}

pub fn writeResourceSection(out: []u8, resources: []const Resource) void {
    wU32(out, 0, @intCast(resources.len));
    var names_len: usize = 0;
    for (resources) |resource| {
        if (resource.typ == RSRC_TYPE_FILE) names_len += resource.name.len + 1;
    }
    const header_len = 4 + resources.len * RSRC_ENTRY_SIZE;
    var name_cursor = header_len;
    var data_cursor = header_len + names_len;
    var icon_index: u16 = 0;
    for (resources, 0..) |resource, index| {
        const payload = resourcePayload(resource);
        data_cursor = alignForward(data_cursor, 16);
        const off = 4 + index * RSRC_ENTRY_SIZE;
        wU16(out, off + 0, resource.typ);
        var entry_index: u16 = 0;
        var name_off: usize = 0;
        if (resource.typ == RSRC_TYPE_ICON) {
            entry_index = icon_index;
            icon_index += 1;
        } else if (resource.typ == RSRC_TYPE_FILE) {
            name_off = name_cursor;
            var i: usize = 0;
            while (i < resource.name.len) : (i += 1) out[name_cursor + i] = resource.name[i];
            out[name_cursor + resource.name.len] = 0;
            name_cursor += resource.name.len + 1;
        }
        wU16(out, off + 2, entry_index);
        wU32(out, off + 4, @intCast(name_off));
        wU32(out, off + 8, @intCast(data_cursor));
        wU32(out, off + 12, @intCast(payload.len));
        @memcpy(out[data_cursor .. data_cursor + payload.len], payload);
        data_cursor += payload.len;
    }
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        const lx = if (x >= 'A' and x <= 'Z') x + 32 else x;
        const ly = if (y >= 'A' and y <= 'Z') y + 32 else y;
        if (lx != ly) return false;
    }
    return true;
}

fn rU16(bytes: []const u8, off: usize) u16 {
    return @as(u16, bytes[off]) | (@as(u16, bytes[off + 1]) << 8);
}

fn rU32(bytes: []const u8, off: usize) u32 {
    return @as(u32, bytes[off]) | (@as(u32, bytes[off + 1]) << 8) | (@as(u32, bytes[off + 2]) << 16) | (@as(u32, bytes[off + 3]) << 24);
}

fn importCount(import_set: ImportSet) usize {
    return switch (import_set) {
        .console => 1,
        .desktop_ok => 3,
    };
}

fn importModule(import_set: ImportSet, index: usize) []const u8 {
    return switch (import_set) {
        .console => "R4SYS",
        .desktop_ok => switch (index) {
            0 => "R4SYS",
            1 => "R4DESK",
            2 => "R4DRAW",
            else => "",
        },
    };
}

fn importSymbol(import_set: ImportSet, index: usize) []const u8 {
    _ = import_set;
    _ = index;
    return "Query";
}

fn importMinVersion(import_set: ImportSet, index: usize) u32 {
    _ = import_set;
    _ = index;
    return 1;
}

fn importFlags(import_set: ImportSet, index: usize) u32 {
    _ = import_set;
    _ = index;
    return 0;
}

fn fail(message: []const u8) PackResult {
    return .{ .ok = false, .err = message };
}

fn writeSection(image: []u8, off: usize, name: []const u8, flags: u32, file_off: u32, file_size: u32, mem_size: u32, alignment: u32) void {
    var i: usize = 0;
    while (i < 8 and i < name.len) : (i += 1) image[off + i] = name[i];
    wU32(image, off + 8, flags);
    wU32(image, off + 12, file_off);
    wU32(image, off + 16, file_size);
    wU32(image, off + 20, mem_size);
    wU32(image, off + 24, alignment);
    wU32(image, off + 28, 0);
}

fn putZ(image: []u8, cursor: *usize, text: []const u8) usize {
    const start = cursor.*;
    if (text.len != 0) @memcpy(image[start .. start + text.len], text);
    cursor.* += text.len;
    image[cursor.*] = 0;
    cursor.* += 1;
    return start;
}

fn alignForward(value: usize, alignment: usize) usize {
    return (value + alignment - 1) & ~(alignment - 1);
}

fn wU16(image: []u8, off: usize, value: u16) void {
    image[off + 0] = @intCast(value & 0xff);
    image[off + 1] = @intCast((value >> 8) & 0xff);
}

fn wU32(image: []u8, off: usize, value: u32) void {
    image[off + 0] = @intCast(value & 0xff);
    image[off + 1] = @intCast((value >> 8) & 0xff);
    image[off + 2] = @intCast((value >> 16) & 0xff);
    image[off + 3] = @intCast((value >> 24) & 0xff);
}
