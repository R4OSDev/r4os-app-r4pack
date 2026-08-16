const r4os = @import("r4os");

const R4M_HEADER_SIZE: usize = 64;
const R4M_SECTION_SIZE: usize = 32;
const R4M_ENTRY_SIZE: usize = 16;
const R4M_IMPORT_SIZE: usize = 16;
const R4M_EXPORT_SIZE: usize = 16;
const R4M_RELOCATION_SIZE: usize = 24;
const ARCH_X86_64: u16 = 1;
const R4M_VERSION: u16 = 1;

const R4X_FLAG_APP_CLASS_CONSOLE: u32 = 0x00000001;
const R4X_FLAG_APP_CLASS_GUI: u32 = 0x00000002;
const R4X_FLAG_APP_CLASS_SERVICE: u32 = 0x00000004;
const R4X_KNOWN_FLAGS: u32 = R4X_FLAG_APP_CLASS_CONSOLE | R4X_FLAG_APP_CLASS_GUI | R4X_FLAG_APP_CLASS_SERVICE;

const R4M_SECTION_FLAG_ALLOC: u32 = 0x00000001;
const R4M_SECTION_FLAG_EXEC: u32 = 0x00000002;
const R4M_SECTION_FLAG_WRITE: u32 = 0x00000004;
const R4M_SECTION_FLAG_BSS: u32 = 0x00000008;

const R4M_RELOC_ABS64: u32 = 1;
const R4M_RELOC_REL32: u32 = 2;
const R4M_RELOC_BASE_REL64: u32 = 3;
const R4M_RELOC_IMPORT_SLOT64: u32 = 4;

const max_file_bytes: usize = 64 * 1024;
const max_sections: usize = 4;
// Inspektion akzeptiert zusaetzlich die non-alloc-Section .rsrc (0.61.12);
// der eigene CLI-Packpfad erzeugt weiterhin hoechstens vier Sections.
const max_inspect_sections: usize = 5;
const max_imports: usize = 16;
const max_exports: usize = 16;
const max_relocations: usize = 32;
const max_metadata: usize = 16;
const path_capacity: usize = 192;
const log_capacity: usize = 8192;

const log_dir = "C:\\SOFTWARE\\R4CODE\\LOGS";
const log_path = "C:\\SOFTWARE\\R4CODE\\LOGS\\R4PACK.LOG";
const self_path = "C:\\SOFTWARE\\R4CODE\\R4PACK.R4X";

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    var app = App{ .sys = r4_app.system() };
    const rc = app.run(trim(zSlice(app.sys.argsRaw())));
    _ = app.flushLog();
    return rc;
}

const ModuleKind = enum(u16) {
    r4x = 1,
    r4l = 2,
    r4d = 3,
    r4p = 4,
    kernel_provider = 5,
    kernel_module_reserved = 6,
};

const AppClass = enum {
    auto,
    console,
    gui,
    service,
};

const ModuleImport = struct {
    module: []const u8,
    symbol: []const u8,
    min_version: u32,
    flags: u32,
};

const ModuleExport = struct {
    name: []const u8,
    section: ?[]const u8,
    offset: u32,
    version: u32,
};

const ModuleRelocation = struct {
    kind: u32,
    patch_section: []const u8,
    patch_offset: u32,
    target_section: []const u8,
    target_offset: u32,
    addend: i32,
};

const InputSection = struct {
    name: []const u8,
    data: []const u8,
    mem_size: u32,
    alignment: u32,
    flags: u32,
};

const Options = struct {
    out: []const u8 = "",
    kind: ModuleKind = .r4x,
    app_class: AppClass = .auto,
    module_name: []const u8 = "APP",
    code_path: []const u8 = "",
    rodata_path: []const u8 = "",
    data_path: []const u8 = "",
    bss_size: u32 = 0,
    imports: [max_imports]ModuleImport = undefined,
    import_count: usize = 0,
    exports: [max_exports]ModuleExport = undefined,
    export_count: usize = 0,
    relocations: [max_relocations]ModuleRelocation = undefined,
    relocation_count: usize = 0,
    metadata: [max_metadata][]const u8 = undefined,
    metadata_count: usize = 0,
};

const Token = struct {
    token: []const u8,
    rest: []const u8,
};

const App = struct {
    sys: r4os.r4sys.Context,
    payload_buffer: [max_file_bytes]u8 = undefined,
    image_buffer: [max_file_bytes]u8 = undefined,
    log_buffer: [log_capacity]u8 = .{0} ** log_capacity,
    log_len: usize = 0,
    log_overflow: bool = false,

    fn run(self: *App, args: []const u8) i32 {
        self.resetLog();
        self.logLine("R4PACK 0.51.47");
        if (args.len == 0 or equalsIgnoreCase(args, "HELP") or equalsIgnoreCase(args, "/?")) {
            self.printUsage();
            return 0;
        }
        if (equalsIgnoreCase(args, "/SELFTEST") or equalsIgnoreCase(args, "SELFTEST")) return self.selfTest();

        var opts = Options{};
        var rest = args;
        while (takeToken(rest)) |current| {
            rest = current.rest;
            if (equalsIgnoreCase(current.token, "--inspect") or equalsIgnoreCase(current.token, "INSPECT")) {
                const path_token = takeToken(rest) orelse {
                    self.logLine("error: --inspect needs path");
                    return 1;
                };
                return if (self.inspectFile(path_token.token)) 0 else 1;
            } else if (equalsIgnoreCase(current.token, "--output")) {
                const value = takeToken(rest) orelse return self.badArgs("--output needs path");
                opts.out = value.token;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--code")) {
                const value = takeToken(rest) orelse return self.badArgs("--code needs path");
                opts.code_path = value.token;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--rodata")) {
                const value = takeToken(rest) orelse return self.badArgs("--rodata needs path");
                opts.rodata_path = value.token;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--data")) {
                const value = takeToken(rest) orelse return self.badArgs("--data needs path");
                opts.data_path = value.token;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--bss-size")) {
                const value = takeToken(rest) orelse return self.badArgs("--bss-size needs value");
                opts.bss_size = parseU32(value.token) orelse return self.badArgs("invalid --bss-size");
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--kind") or equalsIgnoreCase(current.token, "--format")) {
                const value = takeToken(rest) orelse return self.badArgs("--kind needs value");
                opts.kind = parseModuleKind(value.token) orelse return self.badArgs("invalid --kind");
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--r4x")) {
                opts.kind = .r4x;
            } else if (equalsIgnoreCase(current.token, "--r4l")) {
                opts.kind = .r4l;
            } else if (equalsIgnoreCase(current.token, "--r4d")) {
                opts.kind = .r4d;
            } else if (equalsIgnoreCase(current.token, "--r4p")) {
                opts.kind = .r4p;
            } else if (equalsIgnoreCase(current.token, "--app-class")) {
                const value = takeToken(rest) orelse return self.badArgs("--app-class needs value");
                opts.app_class = parseAppClass(value.token) orelse return self.badArgs("invalid --app-class");
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--name") or equalsIgnoreCase(current.token, "--module-name")) {
                const value = takeToken(rest) orelse return self.badArgs("--name needs value");
                opts.module_name = value.token;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--import")) {
                const value = takeToken(rest) orelse return self.badArgs("--import needs value");
                if (opts.import_count >= max_imports) return self.badArgs("too many imports");
                opts.imports[opts.import_count] = parseModuleImport(value.token) orelse return self.badArgs("invalid import");
                opts.import_count += 1;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--export")) {
                const value = takeToken(rest) orelse return self.badArgs("--export needs value");
                if (opts.export_count >= max_exports) return self.badArgs("too many exports");
                opts.exports[opts.export_count] = parseModuleExport(value.token) orelse return self.badArgs("invalid export");
                opts.export_count += 1;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--reloc")) {
                const value = takeToken(rest) orelse return self.badArgs("--reloc needs value");
                if (opts.relocation_count >= max_relocations) return self.badArgs("too many relocations");
                opts.relocations[opts.relocation_count] = parseModuleRelocation(value.token) orelse return self.badArgs("invalid relocation");
                opts.relocation_count += 1;
                rest = value.rest;
            } else if (equalsIgnoreCase(current.token, "--meta")) {
                const value = takeToken(rest) orelse return self.badArgs("--meta needs value");
                if (opts.metadata_count >= max_metadata) return self.badArgs("too many metadata entries");
                opts.metadata[opts.metadata_count] = value.token;
                opts.metadata_count += 1;
                rest = value.rest;
            } else {
                self.logPair("error: unknown argument", current.token);
                return 1;
            }
        }

        return if (self.pack(opts)) 0 else 1;
    }

    fn badArgs(self: *App, text: []const u8) i32 {
        self.logPair("error", text);
        self.printUsage();
        return 1;
    }

    fn printUsage(self: *App) void {
        self.logLine("usage:");
        self.logLine("  R4PACK.R4X --inspect <module.R4X|module.R4L>");
        self.logLine("  R4PACK.R4X --r4x --output <out.R4X> --code <code.bin> --app-class console --import R4SYS:Query:1 --export R4XStart:.text:0:1 --meta r4x.start=r4xstart");
        self.logLine("  R4PACK.R4X /SELFTEST");
    }

    fn pack(self: *App, opts: Options) bool {
        if (opts.out.len == 0) {
            self.logLine("error: --output missing");
            return false;
        }
        if (opts.code_path.len == 0) {
            self.logLine("error: --code missing");
            return false;
        }
        if (opts.module_name.len == 0) {
            self.logLine("error: module name missing");
            return false;
        }

        var payload_len: usize = 0;
        const code = self.readPayloadFile(opts.code_path, &payload_len) orelse {
            self.logPair("code read failed", opts.code_path);
            return false;
        };
        if (code.len == 0) {
            self.logLine("error: empty code section");
            return false;
        }
        const rodata = if (opts.rodata_path.len != 0) self.readPayloadFile(opts.rodata_path, &payload_len) orelse {
            self.logPair("rodata read failed", opts.rodata_path);
            return false;
        } else self.payload_buffer[0..0];
        const data = if (opts.data_path.len != 0) self.readPayloadFile(opts.data_path, &payload_len) orelse {
            self.logPair("data read failed", opts.data_path);
            return false;
        } else self.payload_buffer[0..0];

        var sections: [max_sections]InputSection = undefined;
        var section_count: usize = 0;
        sections[section_count] = .{
            .name = ".text",
            .data = code,
            .mem_size = @intCast(code.len),
            .alignment = 16,
            .flags = R4M_SECTION_FLAG_ALLOC | R4M_SECTION_FLAG_EXEC,
        };
        section_count += 1;
        if (rodata.len != 0) {
            sections[section_count] = .{
                .name = ".rodata",
                .data = rodata,
                .mem_size = @intCast(rodata.len),
                .alignment = 16,
                .flags = R4M_SECTION_FLAG_ALLOC,
            };
            section_count += 1;
        }
        if (data.len != 0) {
            sections[section_count] = .{
                .name = ".data",
                .data = data,
                .mem_size = @intCast(data.len),
                .alignment = 16,
                .flags = R4M_SECTION_FLAG_ALLOC | R4M_SECTION_FLAG_WRITE,
            };
            section_count += 1;
        }
        if (opts.bss_size != 0) {
            sections[section_count] = .{
                .name = ".bss",
                .data = self.payload_buffer[0..0],
                .mem_size = opts.bss_size,
                .alignment = 16,
                .flags = R4M_SECTION_FLAG_ALLOC | R4M_SECTION_FLAG_WRITE | R4M_SECTION_FLAG_BSS,
            };
            section_count += 1;
        }

        return self.writeR4M(opts, sections[0..section_count]);
    }

    fn writeR4M(self: *App, opts: Options, sections: []const InputSection) bool {
        const entry_count: usize = 1;
        const import_count = opts.import_count;
        const export_count = opts.export_count;
        const relocation_count = opts.relocation_count;
        if (sections.len == 0) {
            self.logLine("error: no sections");
            return false;
        }

        var string_len: usize = opts.module_name.len + 1;
        var i: usize = 0;
        while (i < import_count) : (i += 1) {
            string_len += opts.imports[i].module.len + 1;
            string_len += opts.imports[i].symbol.len + 1;
        }
        i = 0;
        while (i < export_count) : (i += 1) string_len += opts.exports[i].name.len + 1;
        i = 0;
        while (i < opts.metadata_count) : (i += 1) string_len += opts.metadata[i].len + 1;

        const section_off = R4M_HEADER_SIZE;
        const entry_off = section_off + sections.len * R4M_SECTION_SIZE;
        const import_off = entry_off + entry_count * R4M_ENTRY_SIZE;
        const export_off = import_off + import_count * R4M_IMPORT_SIZE;
        const reloc_off = export_off + export_count * R4M_EXPORT_SIZE;
        var cursor = alignForward(reloc_off + relocation_count * R4M_RELOCATION_SIZE, 16);

        var section_file_offsets: [max_sections]u32 = undefined;
        i = 0;
        while (i < sections.len) : (i += 1) {
            const section = sections[i];
            if (section.mem_size < section.data.len) {
                self.logLine("error: section mem_size < file_size");
                return false;
            }
            if (section.alignment == 0 or !isPowerOfTwo(section.alignment)) {
                self.logLine("error: bad section alignment");
                return false;
            }
            if (section.data.len == 0) {
                section_file_offsets[i] = 0;
            } else {
                cursor = alignForward(cursor, section.alignment);
                if (cursor > maxU32() or section.data.len > maxU32() - cursor) {
                    self.logLine("error: image too large");
                    return false;
                }
                section_file_offsets[i] = @intCast(cursor);
                cursor += section.data.len;
            }
        }

        const string_off = cursor;
        if (string_len > maxU32() or string_off > maxU32() - string_len) {
            self.logLine("error: image too large");
            return false;
        }
        const total_len = string_off + string_len;
        if (total_len > self.image_buffer.len) {
            self.logLine("error: image too large");
            return false;
        }
        const image = self.image_buffer[0..total_len];
        @memset(image, 0);

        var string_cursor = string_off;
        _ = putZ(image, &string_cursor, opts.module_name);
        var import_module_offsets: [max_imports]u32 = undefined;
        var import_symbol_offsets: [max_imports]u32 = undefined;
        i = 0;
        while (i < import_count) : (i += 1) {
            import_module_offsets[i] = @intCast(putZ(image, &string_cursor, opts.imports[i].module));
            import_symbol_offsets[i] = @intCast(putZ(image, &string_cursor, opts.imports[i].symbol));
        }
        var export_name_offsets: [max_exports]u32 = undefined;
        i = 0;
        while (i < export_count) : (i += 1) {
            export_name_offsets[i] = @intCast(putZ(image, &string_cursor, opts.exports[i].name));
        }
        i = 0;
        while (i < opts.metadata_count) : (i += 1) _ = putZ(image, &string_cursor, opts.metadata[i]);

        @memcpy(image[0..4], "R4M0");
        wU16(image, 4, R4M_VERSION);
        wU16(image, 6, ARCH_X86_64);
        wU16(image, 8, @intFromEnum(opts.kind));
        wU16(image, 10, R4M_HEADER_SIZE);
        wU32(image, 12, r4mFlags(opts.kind, opts.app_class));
        wU32(image, 16, @intCast(section_off));
        wU32(image, 20, @intCast(sections.len));
        wU32(image, 24, if (import_count == 0) 0 else @as(u32, @intCast(import_off)));
        wU32(image, 28, @intCast(import_count));
        wU32(image, 32, if (export_count == 0) 0 else @as(u32, @intCast(export_off)));
        wU32(image, 36, @intCast(export_count));
        wU32(image, 40, if (relocation_count == 0) 0 else @as(u32, @intCast(reloc_off)));
        wU32(image, 44, @intCast(relocation_count));
        wU32(image, 48, @intCast(entry_off));
        wU32(image, 52, @intCast(entry_count));
        wU32(image, 56, @intCast(string_off));
        wU32(image, 60, @intCast(string_len));

        var entry_section_index: u32 = 0;
        i = 0;
        while (i < sections.len) : (i += 1) {
            if ((sections[i].flags & R4M_SECTION_FLAG_EXEC) != 0) {
                entry_section_index = @intCast(i);
                break;
            }
        }

        i = 0;
        while (i < sections.len) : (i += 1) {
            writeSection(
                image,
                section_off + i * R4M_SECTION_SIZE,
                sections[i].name,
                sections[i].flags,
                section_file_offsets[i],
                @intCast(sections[i].data.len),
                sections[i].mem_size,
                sections[i].alignment,
            );
            if (sections[i].data.len != 0) {
                const data_off: usize = @intCast(section_file_offsets[i]);
                @memcpy(image[data_off .. data_off + sections[i].data.len], sections[i].data);
            }
        }

        writeEntry(image, entry_off, entryKindFromModuleKind(opts.kind), entry_section_index, 0, 0);
        i = 0;
        while (i < import_count) : (i += 1) {
            const off = import_off + i * R4M_IMPORT_SIZE;
            wU32(image, off + 0, import_module_offsets[i]);
            wU32(image, off + 4, import_symbol_offsets[i]);
            wU32(image, off + 8, opts.imports[i].min_version);
            wU32(image, off + 12, opts.imports[i].flags);
        }
        i = 0;
        while (i < export_count) : (i += 1) {
            const export_section = if (opts.exports[i].section) |section_name|
                resolveSectionIndex(sections, section_name) orelse {
                    self.logPair("bad export section", section_name);
                    return false;
                }
            else
                entry_section_index;
            const off = export_off + i * R4M_EXPORT_SIZE;
            wU32(image, off + 0, export_name_offsets[i]);
            wU32(image, off + 4, export_section);
            wU32(image, off + 8, opts.exports[i].offset);
            wU32(image, off + 12, opts.exports[i].version);
        }
        i = 0;
        while (i < relocation_count) : (i += 1) {
            const reloc = opts.relocations[i];
            const patch_section = resolveSectionIndex(sections, reloc.patch_section) orelse {
                self.logPair("bad relocation patch section", reloc.patch_section);
                return false;
            };
            const target_section = if (reloc.kind == R4M_RELOC_IMPORT_SLOT64)
                parseImportRelocationTarget(reloc.target_section, import_count) orelse {
                    self.logPair("bad relocation import", reloc.target_section);
                    return false;
                }
            else
                resolveSectionIndex(sections, reloc.target_section) orelse {
                    self.logPair("bad relocation target section", reloc.target_section);
                    return false;
                };
            const off = reloc_off + i * R4M_RELOCATION_SIZE;
            wU32(image, off + 0, reloc.kind);
            wU32(image, off + 4, patch_section);
            wU32(image, off + 8, reloc.patch_offset);
            wU32(image, off + 12, target_section);
            wU32(image, off + 16, reloc.target_offset);
            wU32(image, off + 20, @bitCast(reloc.addend));
        }

        if (!self.inspectImage(opts.out, image)) return false;
        const written = self.writeFile(opts.out, image);
        if (!written) {
            self.logPair("write failed", opts.out);
            return false;
        }
        self.logWrite("R4M0 created: ");
        self.logWrite(opts.out);
        self.logWrite(" (");
        self.logWrite(moduleKindName(@intFromEnum(opts.kind)) orelse "unknown");
        self.logWrite(", ");
        self.logUsize(totalSectionDataSize(sections));
        self.logLine(" code bytes)");
        return true;
    }

    fn inspectFile(self: *App, path: []const u8) bool {
        const bytes = self.readFile(path, self.image_buffer[0..]) orelse {
            self.logPair("inspect read failed", path);
            return false;
        };
        return self.inspectImage(path, bytes);
    }

    fn inspectImage(self: *App, path: []const u8, image: []const u8) bool {
        if (image.len < R4M_HEADER_SIZE) {
            self.logPair("bad R4M0 header", path);
            return false;
        }
        if (!bytesEqual(image[0..4], "R4M0")) {
            self.logPair("bad R4M0 magic", path);
            return false;
        }

        const version = rU16(image, 4);
        const arch = rU16(image, 6);
        const kind_raw = rU16(image, 8);
        const header_size = rU16(image, 10);
        const flags = rU32(image, 12);
        const section_off = rU32(image, 16);
        const section_count = rU32(image, 20);
        const import_off = rU32(image, 24);
        const import_count = rU32(image, 28);
        const export_off = rU32(image, 32);
        const export_count = rU32(image, 36);
        const reloc_off = rU32(image, 40);
        const reloc_count = rU32(image, 44);
        const entry_off = rU32(image, 48);
        const entry_count = rU32(image, 52);
        const meta_off = rU32(image, 56);
        const meta_size = rU32(image, 60);

        if (version != R4M_VERSION or arch != ARCH_X86_64 or header_size != R4M_HEADER_SIZE) {
            self.logPair("bad R4M0 header fields", path);
            return false;
        }
        const kind_name = moduleKindName(kind_raw) orelse {
            self.logPair("bad R4M0 kind", path);
            return false;
        };
        if (kind_raw == @intFromEnum(ModuleKind.r4x)) {
            if ((flags & ~R4X_KNOWN_FLAGS) != 0 or appClassFlagCount(flags) > 1) {
                self.logPair("bad R4X flags", path);
                return false;
            }
        }
        if (section_count == 0 or section_count > max_file_sections()) {
            self.logPair("bad section table", path);
            return false;
        }

        if (!checkTable(image.len, section_off, section_count, R4M_SECTION_SIZE, true)) return self.inspectFail(path, "section table range");
        if (!checkTable(image.len, entry_off, entry_count, R4M_ENTRY_SIZE, true)) return self.inspectFail(path, "entry table range");
        if (!checkTable(image.len, import_off, import_count, R4M_IMPORT_SIZE, false)) return self.inspectFail(path, "import table range");
        if (!checkTable(image.len, export_off, export_count, R4M_EXPORT_SIZE, false)) return self.inspectFail(path, "export table range");
        if (!checkTable(image.len, reloc_off, reloc_count, R4M_RELOCATION_SIZE, false)) return self.inspectFail(path, "relocation table range");
        if (meta_size != 0 and !checkRange(image.len, meta_off, meta_size)) return self.inspectFail(path, "metadata range");

        var section_mem_sizes: [max_inspect_sections]u32 = undefined;
        var idx: usize = 0;
        while (idx < section_count) : (idx += 1) {
            const off = @as(usize, @intCast(section_off)) + idx * R4M_SECTION_SIZE;
            const file_off = rU32(image, off + 12);
            const file_size = rU32(image, off + 16);
            const mem_size = rU32(image, off + 20);
            const alignment = rU32(image, off + 24);
            if (mem_size < file_size or alignment == 0 or !isPowerOfTwo(alignment)) return self.inspectFail(path, "bad section");
            if (file_size != 0 and !checkRange(image.len, file_off, file_size)) return self.inspectFail(path, "section payload range");
            section_mem_sizes[idx] = mem_size;
        }

        idx = 0;
        while (idx < entry_count) : (idx += 1) {
            const off = @as(usize, @intCast(entry_off)) + idx * R4M_ENTRY_SIZE;
            const section_index = rU32(image, off + 4);
            const section_offset = rU32(image, off + 8);
            if (section_index >= section_count) return self.inspectFail(path, "bad entry section");
            if (section_offset >= section_mem_sizes[@intCast(section_index)]) return self.inspectFail(path, "bad entry offset");
        }

        idx = 0;
        while (idx < import_count) : (idx += 1) {
            const off = @as(usize, @intCast(import_off)) + idx * R4M_IMPORT_SIZE;
            if (!checkZ(image, rU32(image, off + 0)) or !checkZ(image, rU32(image, off + 4))) return self.inspectFail(path, "bad import string");
        }

        idx = 0;
        while (idx < export_count) : (idx += 1) {
            const off = @as(usize, @intCast(export_off)) + idx * R4M_EXPORT_SIZE;
            const section_index = rU32(image, off + 4);
            const section_offset = rU32(image, off + 8);
            if (!checkZ(image, rU32(image, off + 0))) return self.inspectFail(path, "bad export string");
            if (section_index >= section_count) return self.inspectFail(path, "bad export section");
            if (section_offset >= section_mem_sizes[@intCast(section_index)]) return self.inspectFail(path, "bad export offset");
        }

        var reloc_abs64: u32 = 0;
        var reloc_rel32: u32 = 0;
        var reloc_base64: u32 = 0;
        var reloc_import64: u32 = 0;
        var reloc_unknown: u32 = 0;
        idx = 0;
        while (idx < reloc_count) : (idx += 1) {
            const off = @as(usize, @intCast(reloc_off)) + idx * R4M_RELOCATION_SIZE;
            const reloc_kind = rU32(image, off + 0);
            const patch_section = rU32(image, off + 4);
            const patch_offset = rU32(image, off + 8);
            const target_section = rU32(image, off + 12);
            const target_offset = rU32(image, off + 16);
            if (patch_section >= section_count) return self.inspectFail(path, "bad relocation patch section");
            const patch_mem_size = section_mem_sizes[@intCast(patch_section)];
            const patch_out_of_range = patch_offset > patch_mem_size or
                (reloc_kind == R4M_RELOC_REL32 and patch_mem_size - patch_offset < 4) or
                ((reloc_kind == R4M_RELOC_ABS64 or reloc_kind == R4M_RELOC_BASE_REL64 or reloc_kind == R4M_RELOC_IMPORT_SLOT64) and patch_mem_size - patch_offset < 8) or
                ((reloc_kind != R4M_RELOC_REL32 and reloc_kind != R4M_RELOC_ABS64 and reloc_kind != R4M_RELOC_BASE_REL64 and reloc_kind != R4M_RELOC_IMPORT_SLOT64) and patch_mem_size - patch_offset < 1);
            if (patch_out_of_range) {
                self.logWrite("  relocation index=");
                self.logUsize(idx);
                self.logWrite(" kind=");
                self.logU32(reloc_kind);
                self.logWrite(" patch_section=");
                self.logU32(patch_section);
                self.logWrite(" patch_offset=");
                self.logU32(patch_offset);
                self.logWrite(" section_mem_size=");
                self.logU32(patch_mem_size);
                self.logLine("");
                return self.inspectFail(path, "bad relocation patch offset");
            }
            if (reloc_kind == R4M_RELOC_IMPORT_SLOT64) {
                if (target_section >= import_count) return self.inspectFail(path, "bad relocation import");
            } else {
                if (target_section >= section_count) return self.inspectFail(path, "bad relocation target section");
                if (target_offset >= section_mem_sizes[@intCast(target_section)]) return self.inspectFail(path, "bad relocation target offset");
            }
            if (reloc_kind == R4M_RELOC_ABS64) reloc_abs64 += 1 else if (reloc_kind == R4M_RELOC_REL32) reloc_rel32 += 1 else if (reloc_kind == R4M_RELOC_BASE_REL64) reloc_base64 += 1 else if (reloc_kind == R4M_RELOC_IMPORT_SLOT64) reloc_import64 += 1 else reloc_unknown += 1;
        }

        const start_value = findMetaValue(image, meta_off, meta_size, "r4x.start=") orelse "unknown";
        const entry_value = findMetaValue(image, meta_off, meta_size, "r4x.entry=") orelse "unknown";
        self.logWrite("R4M0 inspect OK: ");
        self.logWrite(path);
        self.logWrite(" kind=");
        self.logWrite(kind_name);
        self.logWrite(" sections=");
        self.logU32(section_count);
        self.logWrite(" entries=");
        self.logU32(entry_count);
        self.logWrite(" imports=");
        self.logU32(import_count);
        self.logWrite(" exports=");
        self.logU32(export_count);
        self.logWrite(" relocs=");
        self.logU32(reloc_count);
        self.logWrite(" flags=0x");
        self.logHex32(flags);
        if (kind_raw == @intFromEnum(ModuleKind.r4x)) {
            self.logWrite(" r4x.class=");
            self.logWrite(appClassNameFromFlags(flags));
            self.logWrite(" r4x.start=");
            self.logWrite(start_value);
            self.logWrite(" r4x.entry=");
            self.logWrite(entry_value);
        }
        self.logLine("");
        if (reloc_count != 0) {
            self.logWrite("  reloc-types: abs64=");
            self.logU32(reloc_abs64);
            self.logWrite(" rel32=");
            self.logU32(reloc_rel32);
            self.logWrite(" base_rel64=");
            self.logU32(reloc_base64);
            self.logWrite(" import_slot64=");
            self.logU32(reloc_import64);
            self.logWrite(" unknown=");
            self.logU32(reloc_unknown);
            self.logLine("");
        }
        return true;
    }

    fn inspectFail(self: *App, path: []const u8, reason: []const u8) bool {
        self.logWrite("R4M0 inspect FAILED: ");
        self.logWrite(path);
        self.logWrite(" ");
        self.logLine(reason);
        return false;
    }

    fn selfTest(self: *App) i32 {
        self.logLine("selftest");
        _ = self.ensureDirectory("C:\\TEMP");
        if (!self.ensureDirectory("C:\\TEMP\\R4PACK")) return 1;

        var code_path_buf: [path_capacity]u8 = undefined;
        var out_path_buf: [path_capacity]u8 = undefined;
        var module_name_buf: [32]u8 = undefined;
        var import_module_buf: [16]u8 = undefined;
        var import_symbol_buf: [16]u8 = undefined;
        var export_name_buf: [16]u8 = undefined;
        var section_name_buf: [16]u8 = undefined;
        var meta_buffers: [7][64]u8 = undefined;

        const code_path = copyText(code_path_buf[0..], "C:\\TEMP\\R4PACK\\CODE.BIN");
        const out_path = copyText(out_path_buf[0..], "C:\\TEMP\\R4PACK\\PACKTEST.R4X");
        const code = [_]u8{ 0x31, 0xC0, 0xC3 };
        if (!self.writeFile(code_path, code[0..])) {
            self.logLine("selftest code write failed");
            return 1;
        }

        var opts = Options{
            .out = out_path,
            .kind = .r4x,
            .app_class = .console,
            .module_name = copyText(module_name_buf[0..], "R4PACKTEST"),
            .code_path = code_path,
        };
        opts.imports[0] = .{
            .module = copyText(import_module_buf[0..], "R4SYS"),
            .symbol = copyText(import_symbol_buf[0..], "Query"),
            .min_version = 1,
            .flags = 0,
        };
        opts.import_count = 1;
        opts.exports[0] = .{
            .name = copyText(export_name_buf[0..], "R4XStart"),
            .section = copyText(section_name_buf[0..], ".text"),
            .offset = 0,
            .version = 1,
        };
        opts.export_count = 1;
        opts.metadata[0] = copyText(meta_buffers[0][0..], "r4x.name=R4PACKTEST");
        opts.metadata[1] = copyText(meta_buffers[1][0..], "r4x.class=console");
        opts.metadata[2] = copyText(meta_buffers[2][0..], "feature=program-module");
        opts.metadata[3] = copyText(meta_buffers[3][0..], "r4x.start=r4xstart");
        opts.metadata[4] = copyText(meta_buffers[4][0..], "r4x.entry=R4XStart");
        opts.metadata[5] = copyText(meta_buffers[5][0..], "r4x.start_abi=1");
        opts.metadata[6] = copyText(meta_buffers[6][0..], "r4x.context=R4XStartContext");
        opts.metadata_count = 7;

        if (!self.pack(opts)) return 1;
        if (!self.inspectFile(out_path)) return 1;
        if (!self.inspectFile(self_path)) return 1;
        if (!self.inspectFile("C:\\R4OS\\LIBS\\R4STD.R4L")) return 1;
        self.logLine("R4PACK result: OK");
        return 0;
    }

    fn readFile(self: *App, path: []const u8, out: []u8) ?[]const u8 {
        var path_z: [path_capacity]u8 = .{0} ** path_capacity;
        if (!setZResult(path_z[0..], path)) return null;
        const read = self.sys.fileRead(zptr(path_z[0..]), out);
        if (read < 0) return null;
        const len: usize = @intCast(read);
        if (len >= out.len) return null;
        return out[0..len];
    }

    fn readPayloadFile(self: *App, path: []const u8, payload_len: *usize) ?[]const u8 {
        if (payload_len.* >= self.payload_buffer.len) return null;
        const start = payload_len.*;
        const bytes = self.readFile(path, self.payload_buffer[start..]) orelse return null;
        payload_len.* += bytes.len;
        return self.payload_buffer[start..payload_len.*];
    }

    fn writeFile(self: *App, path: []const u8, data: []const u8) bool {
        var path_z: [path_capacity]u8 = .{0} ** path_capacity;
        if (!setZResult(path_z[0..], path)) return false;
        const written = self.sys.fileWrite(zptr(path_z[0..]), data);
        return written >= 0 and @as(usize, @intCast(written)) == data.len;
    }

    fn ensureDirectory(self: *App, path: []const u8) bool {
        if (self.dirExists(path)) return true;
        var path_z: [path_capacity]u8 = .{0} ** path_capacity;
        if (!setZResult(path_z[0..], path)) return false;
        _ = self.sys.dirCreate(zptr(path_z[0..]));
        return self.dirExists(path);
    }

    fn dirExists(self: *App, path: []const u8) bool {
        var path_z: [path_capacity]u8 = .{0} ** path_capacity;
        if (!setZResult(path_z[0..], path)) return false;
        if (self.sys.fileInfo(zptr(path_z[0..]))) |info| return info.exists != 0 and info.is_dir != 0;
        return false;
    }

    fn resetLog(self: *App) void {
        self.log_len = 0;
        self.log_overflow = false;
        @memset(self.log_buffer[0..], 0);
    }

    fn logLine(self: *App, text: []const u8) void {
        self.logWrite(text);
        self.logWrite("\r\n");
    }

    fn logPair(self: *App, label: []const u8, value: []const u8) void {
        self.logWrite(label);
        self.logWrite(": ");
        self.logLine(value);
    }

    fn logWrite(self: *App, text: []const u8) void {
        self.sys.write(text);
        if (text.len == 0) return;
        if (self.log_len >= self.log_buffer.len) {
            self.log_overflow = true;
            return;
        }
        const writable = min(text.len, self.log_buffer.len - self.log_len);
        if (writable < text.len) self.log_overflow = true;
        @memcpy(self.log_buffer[self.log_len .. self.log_len + writable], text[0..writable]);
        self.log_len += writable;
    }

    fn logUsize(self: *App, value: usize) void {
        self.logU64(@intCast(value));
    }

    fn logU32(self: *App, value: u32) void {
        self.logU64(value);
    }

    fn logU64(self: *App, value: u64) void {
        var buf: [20]u8 = undefined;
        var pos = buf.len;
        var n = value;
        if (n == 0) {
            self.logWrite("0");
            return;
        }
        while (n > 0) {
            pos -= 1;
            buf[pos] = '0' + @as(u8, @intCast(n % 10));
            n /= 10;
        }
        self.logWrite(buf[pos..]);
    }

    fn logHex32(self: *App, value: u32) void {
        var buf: [8]u8 = undefined;
        var shift: u5 = 28;
        var index: usize = 0;
        while (index < buf.len) : (index += 1) {
            const nibble: u8 = @intCast((value >> shift) & 0xF);
            buf[index] = if (nibble < 10) '0' + nibble else 'A' + (nibble - 10);
            if (shift == 0) break;
            shift -= 4;
        }
        self.logWrite(buf[0..]);
    }

    fn flushLog(self: *App) bool {
        _ = self.ensureDirectory("C:\\SOFTWARE");
        _ = self.ensureDirectory("C:\\SOFTWARE\\R4CODE");
        _ = self.ensureDirectory(log_dir);
        if (self.log_overflow and self.log_len + 17 < self.log_buffer.len) {
            @memcpy(self.log_buffer[self.log_len .. self.log_len + 17], "\r\nlog truncated\r\n");
            self.log_len += 17;
        }
        const written = self.sys.fileWrite(log_path, self.log_buffer[0..self.log_len]);
        return written >= 0 and @as(usize, @intCast(written)) == self.log_len;
    }
};

fn writeSection(image: []u8, off: usize, name: []const u8, flags: u32, file_off: u32, file_size: u32, mem_size: u32, alignment: u32) void {
    @memset(image[off..][0..8], 0);
    const n = min(name.len, 8);
    @memcpy(image[off .. off + n], name[0..n]);
    wU32(image, off + 8, flags);
    wU32(image, off + 12, file_off);
    wU32(image, off + 16, file_size);
    wU32(image, off + 20, mem_size);
    wU32(image, off + 24, alignment);
    wU32(image, off + 28, 0);
}

fn writeEntry(image: []u8, off: usize, kind: u32, section_index: u32, section_offset: u32, flags: u32) void {
    wU32(image, off + 0, kind);
    wU32(image, off + 4, section_index);
    wU32(image, off + 8, section_offset);
    wU32(image, off + 12, flags);
}

fn wU16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @intCast(value & 0xFF);
    buf[off + 1] = @intCast((value >> 8) & 0xFF);
}

fn wU32(buf: []u8, off: usize, value: u32) void {
    buf[off] = @intCast(value & 0xFF);
    buf[off + 1] = @intCast((value >> 8) & 0xFF);
    buf[off + 2] = @intCast((value >> 16) & 0xFF);
    buf[off + 3] = @intCast((value >> 24) & 0xFF);
}

fn rU16(buf: []const u8, off: usize) u16 {
    return @as(u16, buf[off]) | (@as(u16, buf[off + 1]) << 8);
}

fn rU32(buf: []const u8, off: usize) u32 {
    return @as(u32, buf[off]) |
        (@as(u32, buf[off + 1]) << 8) |
        (@as(u32, buf[off + 2]) << 16) |
        (@as(u32, buf[off + 3]) << 24);
}

fn putZ(image: []u8, cursor: *usize, value: []const u8) usize {
    const off = cursor.*;
    @memcpy(image[off .. off + value.len], value);
    image[off + value.len] = 0;
    cursor.* = off + value.len + 1;
    return off;
}

fn parseModuleKind(value: []const u8) ?ModuleKind {
    if (equalsIgnoreCase(value, "r4x") or equalsIgnoreCase(value, "app") or equalsIgnoreCase(value, "program")) return .r4x;
    if (equalsIgnoreCase(value, "r4l") or equalsIgnoreCase(value, "library")) return .r4l;
    if (equalsIgnoreCase(value, "r4d") or equalsIgnoreCase(value, "driver")) return .r4d;
    if (equalsIgnoreCase(value, "r4p") or equalsIgnoreCase(value, "protocol")) return .r4p;
    return null;
}

fn parseAppClass(value: []const u8) ?AppClass {
    if (equalsIgnoreCase(value, "auto")) return .auto;
    if (equalsIgnoreCase(value, "console")) return .console;
    if (equalsIgnoreCase(value, "gui")) return .gui;
    if (equalsIgnoreCase(value, "service")) return .service;
    return null;
}

fn parseModuleImport(value: []const u8) ?ModuleImport {
    var parts: [4][]const u8 = undefined;
    const count = splitScalar(value, ':', parts[0..]);
    if (count >= 2) {
        if (parts[0].len == 0 or parts[1].len == 0) return null;
        return .{
            .module = parts[0],
            .symbol = parts[1],
            .min_version = if (count >= 3) parseU32(parts[2]) orelse return null else 0,
            .flags = if (count >= 4) parseU32(parts[3]) orelse return null else 0,
        };
    }
    const dot = indexOfScalar(value, '.') orelse return null;
    if (dot == 0 or dot + 1 >= value.len) return null;
    return .{ .module = value[0..dot], .symbol = value[dot + 1 ..], .min_version = 0, .flags = 0 };
}

fn parseModuleExport(value: []const u8) ?ModuleExport {
    if (value.len == 0) return null;
    var parts: [4][]const u8 = undefined;
    const count = splitScalar(value, ':', parts[0..]);
    if (count == 1) return .{ .name = value, .section = null, .offset = 0, .version = 1 };
    if (count == 2) {
        return .{ .name = parts[0], .section = null, .offset = parseU32(parts[1]) orelse return null, .version = 1 };
    }
    if (count == 3 and !looksLikeSectionName(parts[1])) {
        return .{ .name = parts[0], .section = null, .offset = parseU32(parts[1]) orelse return null, .version = parseU32(parts[2]) orelse return null };
    }
    if (count == 3 or count == 4) {
        if (parts[0].len == 0 or parts[1].len == 0 or parts[2].len == 0) return null;
        return .{
            .name = parts[0],
            .section = parts[1],
            .offset = parseU32(parts[2]) orelse return null,
            .version = if (count == 4) parseU32(parts[3]) orelse return null else 1,
        };
    }
    return null;
}

fn parseModuleRelocation(value: []const u8) ?ModuleRelocation {
    var parts: [6][]const u8 = undefined;
    const count = splitScalar(value, ':', parts[0..]);
    if (count < 5) return null;
    return .{
        .kind = parseRelocationKind(parts[0]) orelse return null,
        .patch_section = parts[1],
        .patch_offset = parseU32(parts[2]) orelse return null,
        .target_section = parts[3],
        .target_offset = parseU32(parts[4]) orelse return null,
        .addend = if (count >= 6) parseI32(parts[5]) orelse return null else 0,
    };
}

fn parseRelocationKind(value: []const u8) ?u32 {
    if (equalsIgnoreCase(value, "abs64")) return R4M_RELOC_ABS64;
    if (equalsIgnoreCase(value, "rel32") or equalsIgnoreCase(value, "rip32")) return R4M_RELOC_REL32;
    if (equalsIgnoreCase(value, "base_rel64") or equalsIgnoreCase(value, "baserel64")) return R4M_RELOC_BASE_REL64;
    if (equalsIgnoreCase(value, "import_slot64") or equalsIgnoreCase(value, "import64")) return R4M_RELOC_IMPORT_SLOT64;
    if (startsWith(value, "raw")) return parseU32(value[3..]);
    return parseU32(value);
}

fn parseImportRelocationTarget(value: []const u8, import_count: usize) ?u32 {
    const digits = if (startsWith(value, "import")) value["import".len..] else if (startsWith(value, "#")) value[1..] else value;
    const index = parseU32(digits) orelse return null;
    if (index >= import_count) return null;
    return index;
}

fn splitScalar(value: []const u8, delimiter: u8, out: []([]const u8)) usize {
    var count: usize = 0;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= value.len) : (i += 1) {
        if (i == value.len or value[i] == delimiter) {
            if (count >= out.len) return out.len + 1;
            out[count] = value[start..i];
            count += 1;
            start = i + 1;
        }
    }
    return count;
}

fn looksLikeSectionName(value: []const u8) bool {
    return value.len != 0 and value[0] == '.';
}

fn resolveSectionIndex(sections: []const InputSection, name: []const u8) ?u32 {
    var i: usize = 0;
    while (i < sections.len) : (i += 1) {
        if (equalsIgnoreCase(sections[i].name, name)) return @intCast(i);
    }
    return null;
}

fn entryKindFromModuleKind(kind: ModuleKind) u32 {
    return switch (kind) {
        .r4x => 1,
        .r4l => 2,
        .r4d => 3,
        .r4p => 4,
        else => 0,
    };
}

fn r4mFlags(kind: ModuleKind, app_class: AppClass) u32 {
    if (kind != .r4x) return 0;
    return switch (app_class) {
        .auto => 0,
        .console => R4X_FLAG_APP_CLASS_CONSOLE,
        .gui => R4X_FLAG_APP_CLASS_GUI,
        .service => R4X_FLAG_APP_CLASS_SERVICE,
    };
}

fn moduleKindName(kind: u16) ?[]const u8 {
    return switch (kind) {
        @intFromEnum(ModuleKind.r4x) => "r4x",
        @intFromEnum(ModuleKind.r4l) => "r4l",
        @intFromEnum(ModuleKind.r4d) => "r4d",
        @intFromEnum(ModuleKind.r4p) => "r4p",
        @intFromEnum(ModuleKind.kernel_provider) => "kernel_provider",
        @intFromEnum(ModuleKind.kernel_module_reserved) => "kernel_module_reserved",
        else => null,
    };
}

fn appClassFlagCount(flags: u32) u8 {
    var count: u8 = 0;
    if ((flags & R4X_FLAG_APP_CLASS_CONSOLE) != 0) count += 1;
    if ((flags & R4X_FLAG_APP_CLASS_GUI) != 0) count += 1;
    if ((flags & R4X_FLAG_APP_CLASS_SERVICE) != 0) count += 1;
    return count;
}

fn appClassNameFromFlags(flags: u32) []const u8 {
    if ((flags & R4X_FLAG_APP_CLASS_CONSOLE) != 0) return "console";
    if ((flags & R4X_FLAG_APP_CLASS_GUI) != 0) return "gui";
    if ((flags & R4X_FLAG_APP_CLASS_SERVICE) != 0) return "service";
    return "auto";
}

fn checkTable(image_len: usize, off: u32, count: u32, item_size: usize, required: bool) bool {
    if (count == 0) return !required;
    if (off == 0) return false;
    const bytes = @as(u64, count) * item_size;
    if (bytes > maxU32()) return false;
    return checkRange(image_len, off, @intCast(bytes));
}

fn checkRange(image_len: usize, off_u32: u32, size_u32: u32) bool {
    const off: usize = @intCast(off_u32);
    const size: usize = @intCast(size_u32);
    return off <= image_len and size <= image_len - off;
}

fn checkZ(image: []const u8, off_u32: u32) bool {
    const off: usize = @intCast(off_u32);
    if (off >= image.len) return false;
    var i = off;
    while (i < image.len) : (i += 1) {
        if (image[i] == 0) return true;
    }
    return false;
}

fn findMetaValue(image: []const u8, meta_off_u32: u32, meta_size_u32: u32, prefix: []const u8) ?[]const u8 {
    if (meta_size_u32 == 0 or !checkRange(image.len, meta_off_u32, meta_size_u32)) return null;
    var cursor: usize = @intCast(meta_off_u32);
    const end = cursor + @as(usize, @intCast(meta_size_u32));
    while (cursor < end) {
        const start = cursor;
        while (cursor < end and image[cursor] != 0) : (cursor += 1) {}
        const item = image[start..cursor];
        if (startsWith(item, prefix)) return item[prefix.len..];
        cursor += 1;
    }
    return null;
}

fn totalSectionDataSize(sections: []const InputSection) usize {
    var total: usize = 0;
    for (sections) |section| total += section.data.len;
    return total;
}

fn alignForward(value: usize, alignment: usize) usize {
    if (alignment <= 1) return value;
    const mask = alignment - 1;
    return (value + mask) & ~mask;
}

fn isPowerOfTwo(value: u32) bool {
    return value != 0 and (value & (value - 1)) == 0;
}

fn maxU32() usize {
    return 0xffff_ffff;
}

fn max_file_sections() u32 {
    return @intCast(max_inspect_sections);
}

fn takeToken(text: []const u8) ?Token {
    const value = trim(text);
    if (value.len == 0) return null;
    var i: usize = 0;
    while (i < value.len and !isSpace(value[i])) : (i += 1) {}
    return .{ .token = value[0..i], .rest = trim(value[i..]) };
}

fn parseU32(value: []const u8) ?u32 {
    if (value.len == 0) return null;
    var out: u64 = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return null;
        out = out * 10 + (ch - '0');
        if (out > maxU32()) return null;
    }
    return @intCast(out);
}

fn parseI32(value: []const u8) ?i32 {
    if (value.len == 0) return null;
    if (value[0] == '-') {
        const magnitude = parseU32(value[1..]) orelse return null;
        if (magnitude > 2147483648) return null;
        return -@as(i32, @intCast(magnitude));
    }
    const parsed = parseU32(value) orelse return null;
    if (parsed > 2147483647) return null;
    return @intCast(parsed);
}

fn zSlice(ptr: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    return ptr[0..len];
}

fn zptr(buffer: []const u8) [*:0]const u8 {
    return @ptrCast(buffer.ptr);
}

fn setZ(buffer: []u8, text: []const u8) void {
    @memset(buffer, 0);
    if (buffer.len == 0) return;
    const len = min(buffer.len - 1, text.len);
    if (len > 0) @memcpy(buffer[0..len], text[0..len]);
    buffer[len] = 0;
}

fn setZResult(buffer: []u8, text: []const u8) bool {
    if (buffer.len == 0 or text.len + 1 > buffer.len) return false;
    setZ(buffer, text);
    return true;
}

fn copyText(buffer: []u8, text: []const u8) []const u8 {
    if (!setZResult(buffer, text)) return "";
    return buffer[0..text.len];
}

fn trim(value: []const u8) []const u8 {
    var start: usize = 0;
    var end = value.len;
    while (start < end and isSpace(value[start])) : (start += 1) {}
    while (end > start and isSpace(value[end - 1])) : (end -= 1) {}
    return value[start..end];
}

fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}

fn startsWith(value: []const u8, prefix: []const u8) bool {
    if (prefix.len > value.len) return false;
    return bytesEqual(value[0..prefix.len], prefix);
}

fn indexOfScalar(value: []const u8, needle: u8) ?usize {
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (value[i] == needle) return i;
    }
    return null;
}

fn bytesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (asciiLower(a[i]) != asciiLower(b[i])) return false;
    }
    return true;
}

fn asciiLower(ch: u8) u8 {
    if (ch >= 'A' and ch <= 'Z') return ch + ('a' - 'A');
    return ch;
}

fn min(a: usize, b: usize) usize {
    return if (a < b) a else b;
}
