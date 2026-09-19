// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include "core/file_sys/fssystem/fs_i_storage.h"

namespace Core::Crypto {
using Key128 = std::array<u8, 16>;
using Key256 = std::array<u8, 32>;

// EVP contexts are local to each operation: reads from different emulation threads
// must never share mutable AES counter state. Nintendo encodes XTS tweaks big-endian.
bool DecryptEcb(const Key128& key, std::span<u8> data);
bool TranscodeCtr(const Key128& key, const Key128& iv, std::span<u8> data);
bool DecryptXts(const Key256& key, uint64_t sector, std::span<u8> data);
Key128 MakeCounter(uint64_t upper, uint64_t byte_offset);

class KeyStore {
public:
    static KeyStore& Instance();
    explicit KeyStore(const std::filesystem::path& directory);
    bool HasProductionKeys() const { return production_keys_loaded; }
    std::optional<Key128> GetKey(const std::string& name) const;
    std::optional<Key256> GetHeaderKey() const;
    std::optional<Key128> GetTitleKey(const Key128& rights_id) const;
    bool AddTicket(const FileSys::VirtualFile& file);

private:
    void ReadKeys(const std::filesystem::path& path, bool titles);
    void DeriveKeys();
    std::map<std::string, std::vector<u8>> keys;
    std::map<Key128, Key128> title_keys;
    mutable std::mutex mutex;
    bool production_keys_loaded = false;
};

class CtrStorage final : public FileSys::IReadOnlyStorage {
public:
    CtrStorage(FileSys::VirtualFile base, Key128 key, uint64_t upper, uint64_t counter_offset);
    size_t Read(u8* buffer, size_t size, size_t offset) const override;
    size_t GetSize() const override { return base->GetSize(); }
private:
    FileSys::VirtualFile base;
    Key128 key;
    uint64_t upper;
    uint64_t counter_offset;
};

class XtsStorage final : public FileSys::IReadOnlyStorage {
public:
    XtsStorage(FileSys::VirtualFile base, Key256 key, uint64_t first_sector = 0);
    size_t Read(u8* buffer, size_t size, size_t offset) const override;
    size_t GetSize() const override { return base->GetSize(); }
private:
    FileSys::VirtualFile base;
    Key256 key;
    uint64_t first_sector;
};
} // namespace Core::Crypto
