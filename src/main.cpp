// recomp-tool - Xbox 360 / PS2 Reverse Engineering CLI
#include "xex_file.h"
#include "extract.h"
#include "convert.h"
#include "patch.h"
#include "info.h"
#include "modify.h"
#include "idc.h"
#include "xml.h"
#include "ghidra_detect.h"
#include "ghidra_plugins.h"
#include "export_rexglue.h"
#include "export_ps2recomp.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

static void usage() {
    std::cout << "recomp-tool - Xbox 360 / PS2 Reverse Engineering CLI\n\n"
              << "Commands:\n"
              << "  info          <file.xex>                    Show XEX metadata\n"
              << "  list          <file.xex>                    Extended info\n"
              << "  extract       <file.xex> [out]              Extract PE\n"
              << "  decrypt       <file.xex> <out>              Remove encryption\n"
              << "  compress      <file.xex> <out> [enc|unenc]  LZX compress\n"
              << "  decompress    <file.xex> <out>              Decompress to basic\n"
              << "  binary        <file.xex> <out>              Flat binary\n"
              << "  patch         <base.xex> <patch.xexp> <out> Apply XEXP delta\n"
              << "  machine       <file.xex> <d|r> <out>        Force machine type\n"
              << "  remove-limits <file.xex> <opts> <out>       Strip limits\n"
              << "  resources     <file.xex> [dir]              Dump resources\n"
              << "  idc           <file.xex> <out.idc>          IDC script\n"
              << "  xml           <file.xex> [opts]             XML output\n"
              << "\n"
              << "  ghidra-setup                               Detect Ghidra + install plugins\n"
              << "  analyze        <file> <out> [ps2|xbox360]   Ghidra headless analysis\n"
              << "\n"
              << "  export-rexglue  --db <db> --project <name>  ReXGlue TOML\n"
              << "  export-ps2recomp --db <db> --elf <name>     PS2Recomp TOML/CSV\n";
}

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { std::cerr << "Cannot open: " << path << "\n"; exit(1); }
    size_t sz = f.tellg(); f.seekg(0);
    std::vector<uint8_t> data(sz);
    f.read(reinterpret_cast<char*>(data.data()), sz);
    return data;
}

static void write_file(const std::string& path, const uint8_t* data, size_t n) {
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::cerr << "Cannot write: " << path << "\n"; exit(1); }
    f.write(reinterpret_cast<const char*>(data), n);
}

static std::string getArg(int argc, char** argv, int idx, const std::string& def = "") {
    return (idx < argc) ? argv[idx] : def;
}

static int cmd_info(int argc, char** argv) {
    if (argc < 3) { std::cerr << "Usage: recomp-tool info <file.xex>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    xex::print_info(x, false);
    return 0;
}

static int cmd_list(int argc, char** argv) {
    if (argc < 3) { std::cerr << "Usage: recomp-tool list <file.xex>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    xex::print_info(x, true);
    return 0;
}

static int cmd_extract(int argc, char** argv) {
    if (argc < 3) { std::cerr << "Usage: recomp-tool extract <file.xex> [out]\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    std::string out = getArg(argc, argv, 3, "basefile.exe");
    xex::extract_basefile(x, out);
    std::cout << "Extracted: " << out << " (" << fs::file_size(out) << " bytes)\n";
    return 0;
}

static int cmd_decrypt(int argc, char** argv) {
    if (argc < 4) { std::cerr << "Usage: recomp-tool decrypt <file.xex> <out.xex>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    auto result = xex::set_encryption(x, false);
    write_file(argv[3], result.data(), result.size());
    std::cout << "Decrypted: " << argv[3] << "\n";
    return 0;
}

static int cmd_compress(int argc, char** argv) {
    if (argc < 4) { std::cerr << "Usage: recomp-tool compress <file.xex> <out>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    bool encrypt = (argc > 4 && std::string(argv[4]) == "enc");
    auto result = xex::compress_to_normal(x, encrypt);
    write_file(argv[3], result.data(), result.size());
    std::cout << "Compressed: " << argv[3] << "\n";
    return 0;
}

static int cmd_decompress(int argc, char** argv) {
    if (argc < 4) { std::cerr << "Usage: recomp-tool decompress <file.xex> <out>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    auto result = xex::decompress_to_basic(x);
    write_file(argv[3], result.data(), result.size());
    std::cout << "Decompressed: " << argv[3] << "\n";
    return 0;
}

static int cmd_binary(int argc, char** argv) {
    if (argc < 4) { std::cerr << "Usage: recomp-tool binary <file.xex> <out>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    auto result = xex::decompress_to_basic(x, true);
    write_file(argv[3], result.data(), result.size());
    std::cout << "Binary: " << argv[3] << "\n";
    return 0;
}

static int cmd_patch(int argc, char** argv) {
    if (argc < 5) { std::cerr << "Usage: recomp-tool patch <base.xex> <patch.xexp> <out.xex>\n"; return 1; }
    auto base = read_file(argv[2]);
    auto patch = read_file(argv[3]);
    auto result = xex::apply_patch(base, patch);
    write_file(argv[4], result.data(), result.size());
    std::cout << "Patched: " << argv[4] << " (" << result.size() << " bytes)\n";
    return 0;
}

static int cmd_machine(int argc, char** argv) {
    if (argc < 5) { std::cerr << "Usage: recomp-tool machine <file.xex> <d|r> <out>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    bool to_devkit = (std::string(argv[3]) == "d");
    auto result = xex::convert_machine(x, to_devkit);
    write_file(argv[4], result.data(), result.size());
    std::cout << "Machine type: " << (to_devkit ? "devkit" : "retail") << "\n";
    return 0;
}

static int cmd_remove_limits(int argc, char** argv) {
    if (argc < 5) { std::cerr << "Usage: recomp-tool remove-limits <file.xex> <opts> <out>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    auto result = xex::remove_limitations(x, argv[3]);
    write_file(argv[4], result.data(), result.size());
    std::cout << "Limits removed: " << argv[3] << "\n";
    return 0;
}

static int cmd_resources(int argc, char** argv) {
    if (argc < 3) { std::cerr << "Usage: recomp-tool resources <file.xex> [dir]\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    std::string outdir = getArg(argc, argv, 3, "resources");
    fs::create_directories(outdir);
    int count = xex::dump_resources(x, outdir);
    std::cout << "Dumped " << count << " resources to " << outdir << "\n";
    return 0;
}

static int cmd_idc(int argc, char** argv) {
    if (argc < 4) { std::cerr << "Usage: recomp-tool idc <file.xex> <out.idc>\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    std::string idc = xex::make_idc(x);
    std::ofstream f(argv[3]);
    f << idc;
    f.close();
    std::cout << "IDC script: " << argv[3] << " (" << idc.size() << " bytes)\n";
    return 0;
}

static int cmd_xml(int argc, char** argv) {
    if (argc < 3) { std::cerr << "Usage: recomp-tool xml <file.xex> [opts]\n"; return 1; }
    auto data = read_file(argv[2]);
    auto x = xex::XexFile::parse(std::move(data));
    std::string opts = getArg(argc, argv, 3, "a");
    xex::print_xml(x, opts);
    return 0;
}

static int cmd_ghidra_setup(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "Detecting Ghidra installation...\n";
    auto ghidra = find_ghidra();
    if (!ghidra.found) {
        std::cout << "\nGhidra NOT FOUND\n\n";
        std::cout << "Install from: https://ghidra-sre.org/\n";
        std::cout << "Then: export GHIDRA_HOME=/path/to/ghidra\n";
        return 1;
    }
    std::cout << "Found Ghidra " << ghidra.version << " at " << ghidra.path << "\n";
    std::cout << "Java: " << (ghidra.has_java ? "OK" : "NOT FOUND") << "\n";
    if (!ghidra.has_java) { std::cerr << "ERROR: Java not found\n"; return 1; }
    std::cout << "\nChecking plugins...\n";
    check_and_install_all(ghidra);
    std::cout << "\nSetup complete.\n";
    return 0;
}

static int cmd_analyze(int argc, char** argv) {
    if (argc < 4) { std::cerr << "Usage: recomp-tool analyze <file> <out> [ps2|xbox360]\n"; return 1; }
    auto ghidra = find_ghidra();
    if (!ghidra.found) { std::cerr << "Ghidra not found. Run: recomp-tool ghidra-setup\n"; return 1; }

    std::string input = argv[2], output = argv[3];
    std::string platform = getArg(argc, argv, 4, "auto");

    if (platform == "auto") {
        std::string ext = fs::path(input).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".xex") platform = "xbox360";
        else if (ext == ".elf") platform = "ps2";
        else {
            std::ifstream f(input, std::ios::binary);
            char magic[4] = {}; f.read(magic, 4);
            if (memcmp(magic, "XEX2", 4) == 0) platform = "xbox360";
            else if ((unsigned char)magic[0] == 0x7f) platform = "ps2";
        }
    }

    fs::create_directories(output);
    std::string spec = (platform == "ps2") ? "EmotionEngine:LE:32:default" : "PowerPC:BE:32:default";
    std::string proj = output + "/ghidra_project";
    fs::create_directories(proj);

    std::string cmd = ghidra.analyze_headless + " \"" + proj + "\" analysis"
        + " -import \"" + input + "\" -processor " + spec
        + " -analysisTimeoutPerFile 600 -deleteProject 2>&1";

    std::cout << "Ghidra analysis: " << platform << " (" << spec << ")\n";
    std::cout << "  " << input << " -> " << output << "\n\n";
    return system(cmd.c_str());
}

static int cmd_export_rexglue(int argc, char** argv) {
    std::string db, proj, file, outdir;
    bool all = false;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--db" && i+1 < argc) db = argv[++i];
        else if (a == "--project-name" && i+1 < argc) proj = argv[++i];
        else if (a == "--file-path" && i+1 < argc) file = argv[++i];
        else if (a == "--out-directory" && i+1 < argc) outdir = argv[++i];
        else if (a == "--all-functions") all = true;
    }
    if (db.empty() || proj.empty()) {
        std::cerr << "Usage: recomp-tool export-rexglue --db <db> --project-name <name>\n";
        return 1;
    }
    std::cout << export_rexglue_toml(db, proj, file, outdir, all);
    return 0;
}

static int cmd_export_ps2recomp(int argc, char** argv) {
    std::string db, elf;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--db" && i+1 < argc) db = argv[++i];
        else if (a == "--elf-name" && i+1 < argc) elf = argv[++i];
    }
    if (db.empty() || elf.empty()) {
        std::cerr << "Usage: recomp-tool export-ps2recomp --db <db> --elf-name <name>\n";
        return 1;
    }
    std::ofstream tf("ps2recomp_config.toml"); tf << export_ps2recomp_toml(db, elf);
    std::ofstream cf("functions.csv"); cf << export_ps2recomp_csv(db, elf);
    std::cout << "PS2Recomp TOML: ps2recomp_config.toml\nPS2Recomp CSV: functions.csv\n";
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    std::string cmd = argv[1];
    if (cmd == "info")             return cmd_info(argc, argv);
    if (cmd == "list")             return cmd_list(argc, argv);
    if (cmd == "extract")          return cmd_extract(argc, argv);
    if (cmd == "decrypt")          return cmd_decrypt(argc, argv);
    if (cmd == "compress")         return cmd_compress(argc, argv);
    if (cmd == "decompress")       return cmd_decompress(argc, argv);
    if (cmd == "binary")           return cmd_binary(argc, argv);
    if (cmd == "patch")            return cmd_patch(argc, argv);
    if (cmd == "machine")          return cmd_machine(argc, argv);
    if (cmd == "remove-limits")    return cmd_remove_limits(argc, argv);
    if (cmd == "resources")        return cmd_resources(argc, argv);
    if (cmd == "idc")              return cmd_idc(argc, argv);
    if (cmd == "xml")              return cmd_xml(argc, argv);
    if (cmd == "ghidra-setup")     return cmd_ghidra_setup(argc, argv);
    if (cmd == "analyze")          return cmd_analyze(argc, argv);
    if (cmd == "export-rexglue")   return cmd_export_rexglue(argc, argv);
    if (cmd == "export-ps2recomp") return cmd_export_ps2recomp(argc, argv);
    usage(); return 1;
}
