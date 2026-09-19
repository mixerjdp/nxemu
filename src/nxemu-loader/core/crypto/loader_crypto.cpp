// SPDX-License-Identifier: GPL-3.0-or-later
// NCA key derivation, counter layout and common-ticket handling follow
// Eden/yuzu's core/crypto/key_manager and file_sys/fssystem implementations.
#include "loader_crypto.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <openssl/evp.h>
#include <fmt/format.h>
#include "yuzu_common/fs/path_util.h"
#include "yuzu_common/logging/log.h"

namespace Core::Crypto {
namespace {
bool Cipher(const EVP_CIPHER* algorithm, const u8* key, const u8* iv, std::span<u8> data) {
    if (data.size() > static_cast<size_t>(std::numeric_limits<int>::max())) return false;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), algorithm, nullptr, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) return false;
    int written = 0;
    if (EVP_DecryptUpdate(ctx.get(), data.data(), &written, data.data(), static_cast<int>(data.size())) != 1 ||
        written != static_cast<int>(data.size())) return false;
    std::array<u8, 16> final{};
    int final_size = 0;
    return EVP_DecryptFinal_ex(ctx.get(), final.data(), &final_size) == 1 && final_size == 0;
}
std::optional<std::vector<u8>> ParseHex(std::string_view text) {
    if (text.size() % 2 != 0) return std::nullopt;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<u8> result(text.size() / 2);
    for (size_t i = 0; i < result.size(); ++i) {
        const int hi = digit(text[2*i]), lo = digit(text[2*i+1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        result[i] = static_cast<u8>((hi << 4) | lo);
    }
    return result;
}
}
bool DecryptEcb(const Key128& key, std::span<u8> data) {
    return data.size() % 16 == 0 && Cipher(EVP_aes_128_ecb(), key.data(), nullptr, data);
}
bool TranscodeCtr(const Key128& key, const Key128& iv, std::span<u8> data) {
    return Cipher(EVP_aes_128_ctr(), key.data(), iv.data(), data);
}
Key128 MakeCounter(uint64_t upper, uint64_t byte_offset) {
    Key128 iv{};
    uint64_t lower = byte_offset / 16;
    for (int i = 7; i >= 0; --i) {
        iv[i] = static_cast<u8>(upper); upper >>= 8;
        iv[i+8] = static_cast<u8>(lower); lower >>= 8;
    }
    return iv;
}
bool DecryptXts(const Key256& key, uint64_t sector, std::span<u8> data) {
    Key128 iv{};
    for (int i = 15; i >= 8; --i) {
        iv[i] = static_cast<u8>(sector);
        sector >>= 8;
    }
    return data.size() >= 16 && data.size() % 16 == 0 &&
        Cipher(EVP_aes_128_xts(), key.data(), iv.data(), data);
}

KeyStore& KeyStore::Instance() {
    static KeyStore instance([] {
        if (const char* path = std::getenv("NXEMU_KEYS_DIR"); path && *path)
            return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(path)));
        return Common::FS::GetYuzuPath(Common::FS::YuzuPath::YuzuDir) / "keys";
    }());
    return instance;
}
KeyStore::KeyStore(const std::filesystem::path& directory) {
    ReadKeys(directory / "prod.keys", false);
    ReadKeys(directory / "title.keys", true);
    DeriveKeys();
}
void KeyStore::ReadKeys(const std::filesystem::path& path, bool titles) {
    std::ifstream input(path);
    if (!input) return;
    if (!titles) production_keys_loaded = true;
    std::string line;
    while (std::getline(input, line)) {
        line.erase(line.find_first_of("#;") == std::string::npos ? line.size() : line.find_first_of("#;"));
        line.erase(std::remove_if(line.begin(), line.end(), [](unsigned char c) { return std::isspace(c); }), line.end());
        const auto equal = line.find('=');
        if (equal == std::string::npos) continue;
        auto name = line.substr(0, equal);
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const auto value = ParseHex(std::string_view(line).substr(equal + 1));
        if (!value || (value->size() != 16 && value->size() != 32)) continue;
        if (titles) {
            const auto id = ParseHex(name);
            if (!id || id->size() != 16 || value->size() != 16) continue;
            Key128 rights{}, key{};
            std::copy(id->begin(), id->end(), rights.begin());
            std::copy(value->begin(), value->end(), key.begin());
            title_keys.insert_or_assign(rights, key);
        } else keys.insert_or_assign(name, *value);
    }
}
std::optional<Key128> KeyStore::GetKey(const std::string& name) const {
    const auto it = keys.find(name);
    if (it == keys.end() || it->second.size() != 16) return std::nullopt;
    Key128 result{};
    std::copy(it->second.begin(), it->second.end(), result.begin());
    return result;
}
std::optional<Key256> KeyStore::GetHeaderKey() const {
    const auto it = keys.find("header_key");
    if (it == keys.end() || it->second.size() != 32) return std::nullopt;
    Key256 result{};
    std::copy(it->second.begin(), it->second.end(), result.begin());
    return result;
}
void KeyStore::DeriveKeys() {
    const auto kek_source = GetKey("aes_kek_generation_source");
    const auto key_source = GetKey("aes_key_generation_source");
    if (!GetHeaderKey()) {
        auto header_kek = GetKey("header_kek");
        const auto master = GetKey("master_key_00");
        auto source = GetKey("header_kek_source");
        if (!header_kek && master && source && kek_source && key_source) {
            auto kek = *kek_source;
            auto result = *key_source;
            if (DecryptEcb(*master, kek) && DecryptEcb(kek, *source) && DecryptEcb(*source, result))
                header_kek = result;
        }
        const auto source256 = keys.find("header_key_source");
        if (header_kek && source256 != keys.end() && source256->second.size() == 32) {
            auto result = source256->second;
            if (DecryptEcb(*header_kek, result)) keys["header_key"] = std::move(result);
        }
    }
    for (int revision = 0; revision < 0x20; ++revision) {
        const auto master = GetKey(fmt::format("master_key_{:02x}", revision));
        if (!master) continue;
        if (auto title_source = GetKey("titlekek_source")) {
            const auto name = fmt::format("titlekek_{:02x}", revision);
            if (!GetKey(name) && DecryptEcb(*master, *title_source))
                keys[name] = {title_source->begin(), title_source->end()};
        }
        if (!kek_source || !key_source) continue;
        for (const auto* type : {"application", "ocean", "system"}) {
            const auto name = fmt::format("key_area_key_{}_{:02x}", type, revision);
            auto source = GetKey(fmt::format("key_area_key_{}_source", type));
            if (GetKey(name) || !source) continue;
            auto kek = *kek_source;
            auto result = *key_source;
            if (DecryptEcb(*master, kek) && DecryptEcb(kek, *source) && DecryptEcb(*source, result))
                keys[name] = {result.begin(), result.end()};
        }
    }
}
std::optional<Key128> KeyStore::GetTitleKey(const Key128& rights_id) const {
    std::scoped_lock lock(mutex);
    const auto it = title_keys.find(rights_id);
    return it == title_keys.end() ? std::nullopt : std::optional<Key128>(it->second);
}
bool KeyStore::AddTicket(const FileSys::VirtualFile& file) {
    std::array<u8, 4> signature{};
    if (!file || file->Read(signature.data(), signature.size(), 0) != signature.size()) return false;
    const u32 type = u32(signature[0]) | (u32(signature[1]) << 8) |
                   (u32(signature[2]) << 16) | (u32(signature[3]) << 24);
    size_t body_offset = 0;
    switch (type) {
    case 0x10000: case 0x10003: body_offset = 0x240; break;
    case 0x10001: case 0x10004: body_offset = 0x140; break;
    case 0x10002: case 0x10005: body_offset = 0x80; break;
    default: return false;
    }
    std::array<u8, 0x2c0> body{};
    // Dumpers often strip tickets to the 0x180 bytes covering the fields we use.
    if (file->Read(body.data(), body.size(), body_offset) < 0x170 || body[0x141] != 0)
        return false; // Personalized tickets need a console-specific key, never treat as common.
    Key128 rights{}, key{};
    std::copy_n(body.data() + 0x160, 16, rights.begin());
    std::copy_n(body.data() + 0x40, 16, key.begin());
    if (rights == Key128{}) return false;
    std::scoped_lock lock(mutex);
    title_keys.try_emplace(rights, key);
    return true;
}

CtrStorage::CtrStorage(FileSys::VirtualFile base_, Key128 key_, uint64_t upper_, uint64_t offset_)
    : base(std::move(base_)), key(key_), upper(upper_), counter_offset(offset_) {}
size_t CtrStorage::Read(u8* buffer, size_t size, size_t offset) const {
    if (size == 0 || offset >= GetSize()) return 0;
    size = std::min(size, GetSize() - offset);
    const auto absolute = counter_offset + offset;
    const size_t prefix = absolute % 16;
    // The prefix contains dummy bytes to consume the beginning of the keystream.
    std::vector<u8> work(prefix + size);
    const size_t read = base->Read(work.data() + prefix, size, offset);
    if (!read || !TranscodeCtr(key, MakeCounter(upper, absolute), std::span(work).first(prefix + read))) return 0;
    std::copy_n(work.data() + prefix, read, buffer);
    return read;
}
XtsStorage::XtsStorage(FileSys::VirtualFile base_, Key256 key_, uint64_t first_sector_)
    : base(std::move(base_)), key(key_), first_sector(first_sector_) {}
size_t XtsStorage::Read(u8* buffer, size_t size, size_t offset) const {
    if (size == 0 || offset >= GetSize()) return 0;
    size = std::min(size, GetSize() - offset);
    size_t done = 0;
    while (done < size) {
        const size_t position = offset + done;
        const size_t sector_offset = position - position % 0x200;
        std::array<u8, 0x200> sector{};
        const size_t read = base->Read(sector.data(), sector.size(), sector_offset);
        if (read != sector.size() || !DecryptXts(key, first_sector + sector_offset / 0x200, sector)) break;
        const size_t take = std::min(size - done, sector.size() - position % 0x200);
        std::copy_n(sector.data() + position % 0x200, take, buffer + done);
        done += take;
    }
    return done;
}
} // namespace Core::Crypto
