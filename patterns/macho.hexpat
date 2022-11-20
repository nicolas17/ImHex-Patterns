// Copyright (c) 2022 Nicolás Alvarez <nicolas.alvarez@gmail.com>

#include <std/io.pat>
#include <std/core.pat>
#include <type/guid.pat>

#define MH_MAGIC_64 0xfeedfacf

#define CPU_ARCH_ABI64      0x01000000
#define CPU_ARCH_ABI64_32   0x02000000


enum cpu_type_t: u32 {
    X86 = 7,
    X86_64 = 7 | CPU_ARCH_ABI64,
    ARM = 12,
    ARM64 = 12 | CPU_ARCH_ABI64,
    ARM64_32 = 12 | CPU_ARCH_ABI64_32,
};
enum cpu_subtype_t : u32 {
    ALL = 0
};
enum FileType: u32 {
    MH_OBJECT = 0x1,
    MH_EXECUTE = 0x2,
    MH_FVMLIB = 0x3,
    MH_CORE = 0x4,
    MH_PRELOAD = 0x5,
    MH_DYLIB = 0x6,
    MH_DYLINKER = 0x7,
    MH_BUNDLE = 0x8,
    MH_DYLIB_STUB = 0x9,
    MH_DSYM = 0xa,
    MH_KEXT_BUNDLE = 0xb,
    MH_FILESET = 0xc,
};

bitfield Flags {
    MH_NOUNDEFS : 1;
    MH_INCRLINK : 1;
    MH_DYLDLINK : 1;
    MH_BINDATLOAD : 1;
    MH_PREBOUND : 1;
    MH_SPLIT_SEGS : 1;
    MH_LAZY_INIT : 1;
    MH_TWOLEVEL : 1;
    MH_FORCE_FLAT : 1;
    MH_NOMULTIDEFS : 1;
    MH_NOFIXPREBINDING : 1;
    MH_PREBINDABLE : 1;
    MH_ALLMODSBOUND : 1;
    MH_SUBSECTIONS_VIA_SYMBOLS : 1;
    MH_CANONICAL : 1;
    MH_WEAK_DEFINES : 1;
    MH_BINDS_TO_WEAK : 1;
    MH_ALLOW_STACK_EXECUTION : 1;
    MH_ROOT_SAFE : 1;
    MH_SETUID_SAFE : 1;
    MH_NO_REEXPORTED_DYLIBS : 1;
    MH_PIE : 1;
    MH_DEAD_STRIPPABLE_DYLIB : 1;
    MH_HAS_TLV_DESCRIPTORS : 1;
    MH_NO_HEAP_EXECUTION : 1;
    MH_APP_EXTENSION_SAFE : 1;
    MH_NLIST_OUTOFSYNC_WITH_DYLDINFO : 1;
    MH_SIM_SUPPORT : 1;
    padding:3;
    MH_DYLIB_IN_CACHE : 1;
};

#define LC_REQ_DYLD 0x80000000

enum LoadCommandType: u32 {
    LC_SEGMENT = 0x1,
    LC_SYMTAB = 0x2,
    LC_SYMSEG = 0x3,
    LC_THREAD = 0x4,
    LC_UNIXTHREAD = 0x5,
    LC_LOADFVMLIB = 0x6,
    LC_IDFVMLIB = 0x7,
    LC_IDENT = 0x8,
    LC_FVMFILE = 0x9,
    LC_PREPAGE = 0xa,
    LC_DYSYMTAB = 0xb,
    LC_LOAD_DYLIB = 0xc,
    LC_ID_DYLIB = 0xd,
    LC_LOAD_DYLINKER = 0xe,
    LC_ID_DYLINKER = 0xf,
    LC_PREBOUND_DYLIB = 0x10,
    LC_ROUTINES = 0x11,
    LC_SUB_FRAMEWORK = 0x12,
    LC_SUB_UMBRELLA = 0x13,
    LC_SUB_CLIENT = 0x14,
    LC_SUB_LIBRARY = 0x15,
    LC_TWOLEVEL_HINTS = 0x16,
    LC_PREBIND_CKSUM = 0x17,
    LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD,

    LC_SEGMENT_64 = 0x19,
    LC_ROUTINES_64 = 0x1a,
    LC_UUID = 0x1b,
    LC_RPATH = 0x1c | LC_REQ_DYLD,
    LC_CODE_SIGNATURE = 0x1d,
    LC_SEGMENT_SPLIT_INFO = 0x1e,
    LC_REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD,
    LC_LAZY_LOAD_DYLIB = 0x20,
    LC_ENCRYPTION_INFO = 0x21,
    LC_DYLD_INFO = 0x22,
    LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD,
    LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD,
    LC_VERSION_MIN_MACOSX = 0x24,
    LC_VERSION_MIN_IPHONEOS = 0x25,
    LC_FUNCTION_STARTS = 0x26,
    LC_DYLD_ENVIRONMENT = 0x27,
    LC_MAIN = 0x28 | LC_REQ_DYLD,
    LC_DATA_IN_CODE = 0x29,
    LC_SOURCE_VERSION = 0x2A,
    LC_DYLIB_CODE_SIGN_DRS = 0x2B,
    LC_ENCRYPTION_INFO_64 = 0x2C,
    LC_LINKER_OPTION = 0x2D,
    LC_LINKER_OPTIMIZATION_HINT = 0x2E,
    LC_VERSION_MIN_TVOS = 0x2F,
    LC_VERSION_MIN_WATCHOS = 0x30,
    LC_NOTE = 0x31,
    LC_BUILD_VERSION = 0x32,
    LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD,
    LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD,
    LC_FILESET_ENTRY = 0x35 | LC_REQ_DYLD,
};

struct mach_header_64 {
    u32 magic;
    cpu_type_t cpu_type;
    cpu_subtype_t cpusubtype;
    FileType filetype;
    u32 ncmds;
    u32 sizeofcmds;
    Flags flags;
    u32 reserved;
};

bitfield SegmentFlags {
    SG_HIGHVM:1;
    SG_FVMLIB:1;
    SG_NORELOC:1;
    SG_PROTECTED_VERSION_1:1;
    SG_READ_ONLY:1;
    padding:24;
};
bitfield vm_prot_t {
    PROT_READ:1;
    PROT_WRITE:1;
    PROT_EXECUTE:1;
    padding:24;
};
struct section_64 {
    char sectname[16];
    char segname[16];
    u64 addr;
    u64 size;
    u32 offset;
    u32 align;
    u32 reloff;
    u32 nreloc;
    u32 flags;
    u32 reserved1;
    u32 reserved2;
    u32 reserved3;
};
struct segment_command_64 {
    char name[16];
    u64 vmaddr;
    u64 vmsize;
    u64 fileoff;
    u64 filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    u32 nsects;
    SegmentFlags flags;
    section_64 sections[nsects];
};
struct dyld_info_command {
    u32 rebase_off;
    u32 rebase_size;

    u32 bind_off;
    u32 bind_size;

    u32 weak_bind_off;
    u32 weak_bind_size;

    u32 lazy_bind_off;
    u32 lazy_bind_size;

    u32 export_off;
    u32 export_size;
};
struct symtab_command {
    u32 symoff [[comment("symbol table offset")]];
    u32 nsyms [[comment("number of symbol table entries")]];
    u32 stroff [[comment("string table offset")]];
    u32 strsize [[comment("string table size in bytes")]];
};
struct dysymtab_command {
    u32 ilocalsym [[comment("index to local symbols")]];
    u32 nlocalsym [[comment("number of local symbols")]];

    u32 iextdefsym [[comment("index to externally defined symbols")]];
    u32 nextdefsym [[comment("number of externally defined symbols")]];

    u32 iundefsym [[comment("index to undefined symbols")]];
    u32 nundefsym [[comment("number of undefined symbols")]];

    u32 tocoff [[comment("file offset to table of contents")]];
    u32 ntoc [[comment("number of entries in table of contents")]];

    u32 modtaboff [[comment("file offset to module table")]];
    u32 nmodtab [[comment("number of module table entries")]];

    u32 extrefsymoff [[comment("offset to referenced symbol table")]];
    u32 nextrefsyms [[comment("number of referenced symbol table entries")]];

    u32 indirectsymoff [[comment("file offset to the indirect symbol table")]];
    u32 nindirectsyms [[comment("number of indirect symbol table entries")]];

    u32 extreloff [[comment("offset to external relocation entries")]];
    u32 nextrel [[comment("number of external relocation entries")]];

    u32 locreloff [[comment("offset to local relocation entries")]];
    u32 nlocrel [[comment("number of local relocation entries")]];
};

struct dylinker_command {
    u32 nameoff;
    char name[] @ addressof(parent)+nameoff [[comment("dynamic linker's path name")]];
};

struct uuid_command {
    type::GUID uuid;
};

struct load_command {
    LoadCommandType cmd;
    u32 cmdsize;
    if (cmd == LoadCommandType::LC_SEGMENT_64) {
        segment_command_64 data [[inline]];
    } else if (cmd == LoadCommandType::LC_DYLD_INFO || cmd == LoadCommandType::LC_DYLD_INFO_ONLY) {
        dyld_info_command data [[inline]];
    } else if (cmd == LoadCommandType::LC_SYMTAB) {
        symtab_command data [[inline]];
    } else if (cmd == LoadCommandType::LC_DYSYMTAB) {
        dysymtab_command data [[inline]];
    } else if (cmd == LoadCommandType::LC_LOAD_DYLINKER) {
        dylinker_command data [[inline]];
    } else if (cmd == LoadCommandType::LC_UUID) {
        uuid_command data [[inline]];
    }
    u8 UNKNOWN[cmdsize - ($ - addressof(this))];
};

mach_header_64 header @ 0;
load_command commands[header.ncmds] @ $;

