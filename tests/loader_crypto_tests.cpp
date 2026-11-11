// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <future>
#include <iostream>
#include <stdexcept>
#include <windows.h>
#include <openssl/evp.h>
#include "core/crypto/loader_crypto.h"
#include "core/file_sys/card_image.h"
#include "core/file_sys/content_archive.h"
#include "core/file_sys/submission_package.h"
#include "core/file_sys/program_metadata.h"
#include "core/file_sys/romfs.h"
#include "core/file_sys/vfs/vfs_real.h"
#include "core/file_sys/vfs/vfs_vector.h"
#include "core/file_sys/fssystem/fssystem_compression_configuration.h"
#include "core/file_sys/fssystem/fssystem_nca_file_system_driver.h"
#include "yuzu_common/logging/backend.h"

using namespace Core::Crypto;
using namespace FileSys;
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void Check(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
class Logger final : public IModuleLogger {
    void Log(LogClass, LogLevel level, const char*, unsigned, const char*, const char* message) override {
        if (level >= LogLevel::Warning) std::cerr << message << '\n';
    }
};
template<size_t N> std::array<u8, N> Hex(const char* text) {
    std::array<u8, N> value{};
    for (size_t i = 0; i < N; ++i) value[i] = static_cast<u8>(std::stoul(std::string(text + i*2, 2), nullptr, 16));
    return value;
}
void UnitTests() {
    // NIST SP800-38A known-answer vectors, independent of our encrypt/decrypt path.
    auto key = Hex<16>("2b7e151628aed2a6abf7158809cf4f3c");
    auto plaintext = Hex<16>("6bc1bee22e409f96e93d7e117393172a");
    auto ecb = Hex<16>("3ad77bb40d7a3660a89ecaf32466ef97");
    Check(DecryptEcb(key, ecb) && ecb == plaintext, "AES ECB known answer");
    auto iv = Hex<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    auto ctr = Hex<16>("874d6191b620e3261bef6864990db6ce");
    Check(TranscodeCtr(key, iv, ctr) && ctr == plaintext, "AES CTR known answer");
    std::vector<u8> bytes(0x1200);
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<u8>(i * 7);
    auto encrypted = bytes;
    const uint64_t upper = 0x123456789abcdef0, offset = 0xc00;
    Check(TranscodeCtr(key, MakeCounter(upper, offset), encrypted), "CTR fixture");
    CtrStorage storage(std::make_shared<VectorVfsFile>(encrypted), key, upper, offset);
    auto verify = [&] {
        for (const size_t start : {0, 1, 15, 16, 511, 1023}) {
            std::vector<u8> result(517);
            Check(storage.Read(result.data(), result.size(), start) == result.size(), "CTR read length");
            Check(std::equal(result.begin(), result.end(), bytes.begin() + start), "CTR unaligned read");
        }
    };
    auto concurrent = std::async(std::launch::async, verify);
    verify(); concurrent.get();
    std::array<u8, 32> tail{};
    Check(storage.Read(tail.data(), tail.size(), bytes.size() - 7) == 7, "CTR EOF");
    Check(storage.Read(tail.data(), tail.size(), bytes.size() + 1) == 0, "CTR beyond EOF");
    Key256 xts_key{};
    for (size_t i = 0; i < xts_key.size(); ++i) xts_key[i] = static_cast<u8>(i);
    encrypted = bytes;
    for (size_t pos = 0; pos < encrypted.size(); pos += 512) {
        std::array<u8, 16> tweak{}; // independent big-endian sector encoding
        size_t sector = pos / 512;
        for (int j = 15; j >= 0; --j) { tweak[j] = static_cast<u8>(sector); sector >>= 8; }
        auto* ctx = EVP_CIPHER_CTX_new();
        int length{};
        Check(EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, xts_key.data(), tweak.data()) == 1, "XTS fixture init");
        Check(EVP_EncryptUpdate(ctx, encrypted.data()+pos, &length, bytes.data()+pos, 512) == 1 && length == 512, "XTS fixture encrypt");
        EVP_CIPHER_CTX_free(ctx);
    }
    XtsStorage xts(std::make_shared<VectorVfsFile>(encrypted), xts_key);
    std::array<u8, 1025> out{};
    Check(xts.Read(out.data(), out.size(), 501) == out.size(), "XTS cross-sector read");
    Check(std::equal(out.begin(), out.end(), bytes.begin()+501), "XTS tweak/partial sector");
    // Existing decrypted content must load without consulting keys.
    std::vector<u8> dnca(0xc00);
    NcaHeader header{}; header.magic = NcaHeader::MagicDecrypted; header.sdk_addon_version = 0x000b0000;
    std::memcpy(dnca.data(), &header, sizeof(header));
    NcaReader reader;
    Check(R_SUCCEEDED(reader.Initialize(std::make_shared<VectorVfsFile>(dnca), GetNcaCompressionConfiguration())), "DNCA regression");
    NcaReader truncated;
    Check(R_FAILED(truncated.Initialize(std::make_shared<VectorVfsFile>(std::vector<u8>(3)), GetNcaCompressionConfiguration())), "truncated header rejection");
    std::cout << "PASS: AES ECB/CTR vectors, concurrent unaligned CTR, EOF, XTS sectors, DNCA and truncated header\n";
}
void ErrorTests() {
    // Files without a card-image header must be rejected, on both probe offsets.
    {
        XCI xci(std::make_shared<VectorVfsFile>(std::vector<u8>(0x2000, 0xAB)));
        Check(xci.GetStatus() == LoaderResultStatus::ErrorBadXCIHeader, "garbage XCI magic");
        XCI tiny(std::make_shared<VectorVfsFile>(std::vector<u8>(3)));
        Check(tiny.GetStatus() == LoaderResultStatus::ErrorBadXCIHeader, "truncated XCI");
    }
    // Valid HEAD magic with hfs_offset past EOF exercises the bounds check.
    {
        std::vector<u8> bytes(0x2000, 0);
        std::memcpy(bytes.data() + 0x1100, "HEAD", 4);
        const u64 huge = ~0ull;
        std::memcpy(bytes.data() + 0x1130, &huge, sizeof(huge));
        XCI xci(std::make_shared<VectorVfsFile>(bytes));
        Check(xci.GetStatus() == LoaderResultStatus::ErrorBadXCIHeader, "XCI hfs_offset bounds");
    }
    // PFS0 containers with a bad magic or impossible header are rejected.
    {
        std::vector<u8> bytes(0x100, 0);
        std::memcpy(bytes.data(), "XXXX", 4);
        NSP nsp(std::make_shared<VectorVfsFile>(bytes));
        Check(nsp.GetStatus() == LoaderResultStatus::ErrorBadPFSHeader, "PFS0 magic rejection");
    }
    // Ticket parsing on a private key store: garbage, unknown signature types and
    // personalized tickets are refused; common tickets register their title key.
    {
        KeyStore store(std::filesystem::temp_directory_path() / "nxemu-errtests-no-keys");
        Check(!store.AddTicket(std::make_shared<VectorVfsFile>(std::vector<u8>(0x40, 7))), "garbage ticket");
        auto make_ticket = [](u8 type, u8 sig_low) {
            std::vector<u8> tik(0x400, 0);
            const u8 sig[4] = {sig_low, 0x00, 0x01, 0x00}; // little-endian signature type
            std::memcpy(tik.data(), sig, sizeof(sig));
            u8* body = tik.data() + 0x140;
            for (int i = 0; i < 16; ++i) body[0x40 + i] = static_cast<u8>(0xA0 + i);  // title key
            body[0x141] = type;                                                     // 0 = common
            for (int i = 0; i < 16; ++i) body[0x160 + i] = static_cast<u8>(0x50 + i); // rights id
            return tik;
        };
        Check(store.AddTicket(std::make_shared<VectorVfsFile>(make_ticket(0, 0x04))), "common ticket");
        // Real dumps truncate the ticket body to 0x180 bytes; the fields we need fit inside.
        auto stripped = make_ticket(0, 0x04);
        stripped.resize(0x140 + 0x180);
        Check(store.AddTicket(std::make_shared<VectorVfsFile>(stripped)), "stripped ticket");
        Key128 rights{}, want{};
        for (int i = 0; i < 16; ++i) { rights[i] = static_cast<u8>(0x50 + i); want[i] = static_cast<u8>(0xA0 + i); }
        const auto got = store.GetTitleKey(rights);
        Check(got && *got == want, "titlekey roundtrip");
        Check(!store.AddTicket(std::make_shared<VectorVfsFile>(make_ticket(1, 0x04))), "personalized ticket");
        Check(!store.AddTicket(std::make_shared<VectorVfsFile>(make_ticket(0, 0x77))), "unknown signature type");
    }
    std::cout << "PASS: corrupt XCI/PFS0 rejection, ticket signature/personalization rules\n";
}
LoaderResultStatus ContainerStatus(const char* path) {
    RealVfsFilesystem vfs;
    auto file = vfs.OpenFile(path, VirtualFileOpenMode::Read);
    Check(file != nullptr, "Cannot open container");
    std::string name = file->GetName();
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (name.size() >= 4 && name.substr(name.size() - 4) == ".nsp")
        return NSP(file).GetStatus();
    return XCI(file).GetStatus();
}
// Child invocations re-run against the real container with NXEMU_KEYS_DIR pointed at a
// directory the parent prepared, so missing or malformed keys surface as the statuses
// the frontend reports to the user.
int ErrorChild(const char* mode, const char* path) {
    LoaderResultStatus expected;
    if (!std::strcmp(mode, "empty")) expected = LoaderResultStatus::ErrorMissingProductionKeyFile;
    else if (!std::strcmp(mode, "noheader")) expected = LoaderResultStatus::ErrorMissingHeaderKey;
    else if (!std::strcmp(mode, "badheader")) expected = LoaderResultStatus::ErrorIncorrectHeaderKey;
    else { std::cerr << "unknown mode\n"; return 2; }
    const auto status = ContainerStatus(path);
    Check(status == expected, fmt::format("expected status {} but got {}", static_cast<int>(expected), static_cast<int>(status)));
    std::cout << "PASS: " << mode << " keys -> LoaderResultStatus " << static_cast<int>(expected) << '\n';
    return 0;
}
void KeyErrorTests(const char* rom) {
    char exe[MAX_PATH];
    Check(GetModuleFileNameA(nullptr, exe, MAX_PATH) != 0, "module path");
    const auto root = std::filesystem::temp_directory_path() /
        ("nxemu-keyerr-tests-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    Check(std::filesystem::create_directory(root), "create isolated key-error directory");
    const std::filesystem::path dirs[] = {root / "empty", root / "noheader", root / "badheader"};
    for (const auto& dir : dirs) std::filesystem::create_directories(dir);
    // prod.keys present but underivable -> ErrorMissingHeaderKey.
    { std::ofstream(dirs[1] / "prod.keys") << "master_key_00 = 000102030405060708090A0B0C0D0E0F\n"; }
    // prod.keys with a wrong header_key -> ErrorIncorrectHeaderKey.
    { std::ofstream(dirs[2] / "prod.keys") << "header_key = 0000000000000000000000000000000000000000000000000000000000000000\n"; }
    const char* modes[] = {"empty", "noheader", "badheader"};
    const char* saved = std::getenv("NXEMU_KEYS_DIR");
    const std::string saved_dir = saved ? saved : "";
    for (int i = 0; i < 3; ++i) {
        _putenv_s("NXEMU_KEYS_DIR", dirs[i].string().c_str());
        std::string cmd = "\"" + std::string(exe) + "\" --error " + modes[i] + " \"" + rom + "\"";
        STARTUPINFOA startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        Check(CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                             &startup, &process) != 0,
              std::string("key-error spawn: ") + modes[i]);
        WaitForSingleObject(process.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(process.hProcess, &code);
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
        Check(code == 0, std::string("key-error child: ") + modes[i]);
    }
    _putenv_s("NXEMU_KEYS_DIR", saved_dir.c_str());
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
}
void ProbeXci(const char* path) {
    RealVfsFilesystem vfs;
    auto file = vfs.OpenFile(path, VirtualFileOpenMode::Read);
    Check(file != nullptr, "Cannot open XCI");
    XCI xci(file);
    std::cout << "XCI status=" << static_cast<int>(xci.GetStatus()) << " file_bytes=" << file->GetSize() << '\n';
    Check(xci.GetStatus() == LoaderResultStatus::Success, "XCI structure");
    Check(xci.GetProgramNCAStatus() == LoaderResultStatus::Success, "XCI program NCA decryption");
    auto base = xci.GetNCAByType(NCAContentType::Program);
    Check(base != nullptr && base->GetExeFS() != nullptr && base->RomFS() != nullptr, "base filesystems");
    ProgramMetadata meta;
    Check(meta.Load(base->GetExeFS()->GetFile("main.npdm")) == LoaderResultStatus::Success, "base NPDM");
    std::cout << "PASS: XCI title=" << std::hex << xci.GetProgramTitleID() << std::dec << " main.npdm/ExeFS/RomFS decrypted\n";
    auto update = xci.GetSecurePartitionNSP()->GetNCA(xci.GetProgramTitleID() | 0x800, LoaderContentRecordType::Program, LoaderTitleType::Update);
    for (const auto& [title, content] : xci.GetSecurePartitionNSP()->GetNCAs()) {
        std::cout << "Container content title=" << std::hex << title << std::dec << " entries=" << content.size() << '\n';
    }
    if (update) {
        NCA patched(update->BaseFile(), base.get());
        Check(patched.GetStatus() == LoaderResultStatus::Success, "encrypted BKTR update");
        Check(patched.RomFS() != nullptr && patched.GetExeFS() != nullptr, "update filesystems");
        auto tree = ExtractRomFS(patched.RomFS());
        Check(tree != nullptr && (!tree->GetFiles().empty() || !tree->GetSubdirectories().empty()), "patched RomFS directory");
        ProgramMetadata patched_meta;
        Check(patched_meta.Load(patched.GetExeFS()->GetFile("main.npdm")) == LoaderResultStatus::Success, "update NPDM");
        std::cout << "PASS: embedded update BKTR, patched RomFS directory and updated main.npdm\n";
    } else std::cout << "INFO: container has no parsed embedded program update\n";
    auto control = xci.GetNCAByType(NCAContentType::Control);
    Check(control != nullptr && control->RomFS() != nullptr, "control NCA");
    auto control_tree = ExtractRomFS(control->RomFS());
    Check(control_tree != nullptr && control_tree->GetFile("control.nacp") != nullptr, "control NACP decryption");
    std::cout << "PASS: control.nacp and icon filesystem\n";
}
void ProbeNsp(const char* path) {
    RealVfsFilesystem vfs;
    auto file = vfs.OpenFile(path, VirtualFileOpenMode::Read);
    Check(file != nullptr, "Cannot open NSP");
    NSP nsp(file);
    std::cout << "NSP status=" << static_cast<int>(nsp.GetStatus()) << " file_bytes=" << file->GetSize() << '\n';
    Check(nsp.GetStatus() == LoaderResultStatus::Success, "NSP structure/decryption");
    Check(!nsp.IsExtractedType(), "unexpected extracted NSP");
    const auto program_status = nsp.GetProgramStatus();
    std::cout << "NSP program_status=" << static_cast<int>(program_status) << '\n';
    // Update-only packages report ErrorMissingBKTRBaseRomFS: their RomFS is a patch
    // against the base game, which a standalone container legitimately lacks.
    Check(program_status == LoaderResultStatus::Success ||
              program_status == LoaderResultStatus::ErrorMissingBKTRBaseRomFS,
          "NSP program NCA decryption");
    const auto title = nsp.GetProgramTitleID();
    Check(title != 0, "NSP program title id");
    const auto program = nsp.GetNCA(title, LoaderContentRecordType::Program);
    Check(program != nullptr, "program NCA present");
    if (program->GetExeFS() != nullptr) {
        ProgramMetadata meta;
        Check(meta.Load(program->GetExeFS()->GetFile("main.npdm")) == LoaderResultStatus::Success, "main.npdm");
        std::cout << "PASS: NSP title=" << std::hex << title << std::dec << " main.npdm/ExeFS decrypted\n";
    }
    if (program->RomFS() != nullptr) {
        std::cout << "PASS: NSP RomFS decrypted\n";
    } else {
        std::cout << "INFO: program RomFS requires the base game (update package)\n";
    }
    for (const auto& [t, content] : nsp.GetNCAs()) {
        std::cout << "Container content title=" << std::hex << t << std::dec << " entries=" << content.size() << '\n';
    }
    const auto control = nsp.GetNCA(title, LoaderContentRecordType::Control);
    if (control != nullptr && control->RomFS() != nullptr) {
        const auto control_tree = ExtractRomFS(control->RomFS());
        Check(control_tree != nullptr && control_tree->GetFile("control.nacp") != nullptr, "control NACP decryption");
        std::cout << "PASS: control.nacp and icon filesystem\n";
    } else {
        std::cout << "INFO: no control NCA in this package\n";
    }
}
void Probe(const char* path) {
    std::string name = path;
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (name.size() >= 4 && name.substr(name.size() - 4) == ".nsp") {
        ProbeNsp(path);
    } else {
        ProbeXci(path);
    }
}
int main(int argc, char** argv) {
    Logger logger;
    Common::Log::Initialize(&logger, "*:Warning");
    try {
        if (argc >= 4 && !std::strcmp(argv[1], "--error")) return ErrorChild(argv[2], argv[3]);
        UnitTests();
        ErrorTests();
        if (argc > 1) {
            Probe(argv[1]);
            KeyErrorTests(argv[1]);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
