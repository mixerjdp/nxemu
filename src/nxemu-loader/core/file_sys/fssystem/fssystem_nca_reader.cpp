// SPDX-FileCopyrightText: Copyright 2023 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/file_sys/fssystem/fssystem_nca_file_system_driver.h"
#include "core/file_sys/vfs/vfs_offset.h"
#include <fmt/format.h>
#include "yuzu_common/logging/log.h"

namespace FileSys {

namespace {

constexpr inline u32 SdkAddonVersionMin = 0x000B0000;
constexpr inline size_t Aes128KeySize = 0x10;
constexpr const std::array<u8, Aes128KeySize> ZeroKey{};

constexpr Result CheckNcaMagic(u32 magic) {
    // Verify the magic is not a deprecated one.
    R_UNLESS(magic != NcaHeader::Magic0, ResultUnsupportedSdkVersion);
    R_UNLESS(magic != NcaHeader::Magic1, ResultUnsupportedSdkVersion);
    // Verify the magic is the current one.
    R_UNLESS(magic == NcaHeader::MagicDecrypted || magic == NcaHeader::Magic3 ||
                 magic == NcaHeader::Magic2, ResultInvalidNcaSignature);

    R_SUCCEED();
}

} // namespace

NcaReader::NcaReader()
    : m_body_storage(), m_header_storage(), m_is_software_aes_prioritized(false),
      m_is_available_sw_key(false), m_get_decompressor() {
    std::memset(std::addressof(m_header), 0, sizeof(m_header));
}

NcaReader::~NcaReader() {}

Result NcaReader::Initialize(VirtualFile base_storage, const NcaCompressionConfiguration& compression_cfg) {
    // Validate preconditions.
    ASSERT(base_storage != nullptr);
    ASSERT(m_body_storage == nullptr);

    // Create the work header storage storage.
    VirtualFile work_header_storage;

    // Read the header.
    R_UNLESS(base_storage->ReadObject(std::addressof(m_header), 0) == sizeof(m_header), ResultInvalidNcaHeader);
    work_header_storage = base_storage;
    if (R_FAILED(CheckNcaMagic(m_header.magic))) {
        auto& keys = Core::Crypto::KeyStore::Instance();
        m_load_error = keys.HasProductionKeys() ? LoaderResultStatus::ErrorMissingHeaderKey
                                              : LoaderResultStatus::ErrorMissingProductionKeyFile;
        const auto header_key = keys.GetHeaderKey();
        if (!header_key) {
            LOG_ERROR(Loader, "Encrypted NCA requires header_key in user/keys/prod.keys (or NXEMU_KEYS_DIR). Restart after installing keys.");
            R_THROW(ResultInvalidNcaSignature);
        }
        work_header_storage = std::make_shared<Core::Crypto::XtsStorage>(base_storage, *header_key);
        m_load_error = LoaderResultStatus::ErrorIncorrectHeaderKey;
        R_UNLESS(work_header_storage->ReadObject(std::addressof(m_header), 0) == sizeof(m_header), ResultInvalidNcaHeader);
        R_TRY(CheckNcaMagic(m_header.magic));
    }
    if (m_header.magic == NcaHeader::Magic2) {
        m_load_error = LoaderResultStatus::ErrorNCA2;
        R_THROW(ResultUnsupportedSdkVersion);
    }
    m_load_error = LoaderResultStatus::ErrorBadNCAHeader;
    // Eden derives section keys from the key-area key or a rights-managed title key.
    // DNCA retains its original key fields but must never require production keys.
    if (!IsDecrypted()) {
        auto& keys = Core::Crypto::KeyStore::Instance();
        const unsigned revision = std::max<unsigned>(m_header.GetProperKeyGeneration(), 1) - 1;
        if (m_header.rights_id != Core::Crypto::Key128{}) {
            auto title = keys.GetTitleKey(m_header.rights_id);
            m_load_error = LoaderResultStatus::ErrorMissingTitlekey;
            R_UNLESS(title.has_value(), ResultInvalidNcaHeader);
            const auto kek = keys.GetKey(fmt::format("titlekek_{:02x}", revision));
            m_load_error = LoaderResultStatus::ErrorMissingTitlekek;
            R_UNLESS(kek.has_value(), ResultInvalidNcaHeader);
            R_UNLESS(Core::Crypto::DecryptEcb(*kek, *title), ResultInvalidNcaHeader);
            m_ctr_key = *title;
        } else {
            constexpr const char* types[] = {"application", "ocean", "system"};
            R_UNLESS(m_header.key_index < 3, ResultInvalidNcaKeyIndex);
            const auto area = keys.GetKey(fmt::format("key_area_key_{}_{:02x}", types[m_header.key_index], revision));
            m_load_error = LoaderResultStatus::ErrorMissingKeyAreaKey;
            if (!area) {
                LOG_ERROR(Loader, "Missing key_area_key_{}_{:02x} in prod.keys", types[m_header.key_index], revision);
                R_THROW(ResultInvalidNcaHeader);
            }
            std::array<u8, 0x40> decrypted{};
            std::copy_n(m_header.encrypted_key_area.begin(), decrypted.size(), decrypted.begin());
            R_UNLESS(Core::Crypto::DecryptEcb(*area, decrypted), ResultInvalidNcaHeader);
            std::copy_n(decrypted.begin(), 32, m_xts_key.begin());
            std::copy_n(decrypted.begin() + 32, 16, m_ctr_key.begin());
        }
    }
    m_load_error = LoaderResultStatus::ErrorBadNCAHeader;

    // Validate the sdk version.
    R_UNLESS(m_header.sdk_addon_version >= SdkAddonVersionMin, ResultUnsupportedSdkVersion);

    // Set our decompressor function getter.
    m_get_decompressor = compression_cfg.get_decompressor;

    // Set our storages.
    m_header_storage = std::move(work_header_storage);
    m_body_storage = std::move(base_storage);

    R_SUCCEED();
}

VirtualFile NcaReader::GetSharedBodyStorage() {
    ASSERT(m_body_storage != nullptr);
    return m_body_storage;
}

u32 NcaReader::GetMagic() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.magic;
}

NcaHeader::DistributionType NcaReader::GetDistributionType() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.distribution_type;
}

NcaHeader::ContentType NcaReader::GetContentType() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.content_type;
}

u8 NcaReader::GetHeaderSign1KeyGeneration() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.header1_signature_key_generation;
}

u8 NcaReader::GetKeyGeneration() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.GetProperKeyGeneration();
}

u8 NcaReader::GetKeyIndex() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.key_index;
}

uint64_t NcaReader::GetContentSize() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.content_size;
}

uint64_t NcaReader::GetProgramId() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.program_id;
}

u32 NcaReader::GetContentIndex() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.content_index;
}

u32 NcaReader::GetSdkAddonVersion() const {
    ASSERT(m_body_storage != nullptr);
    return m_header.sdk_addon_version;
}

void NcaReader::GetRightsId(u8* dst, size_t dst_size) const {
    ASSERT(dst != nullptr);
    ASSERT(dst_size >= NcaHeader::RightsIdSize);

    std::memcpy(dst, m_header.rights_id.data(), NcaHeader::RightsIdSize);
}

bool NcaReader::HasFsInfo(s32 index) const {
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);
    return m_header.fs_info[index].start_sector != 0 || m_header.fs_info[index].end_sector != 0;
}

s32 NcaReader::GetFsCount() const {
    ASSERT(m_body_storage != nullptr);
    for (s32 i = 0; i < NcaHeader::FsCountMax; i++) {
        if (!this->HasFsInfo(i)) {
            return i;
        }
    }
    return NcaHeader::FsCountMax;
}

const Hash& NcaReader::GetFsHeaderHash(s32 index) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);
    return m_header.fs_header_hash[index];
}

void NcaReader::GetFsHeaderHash(Hash* dst, s32 index) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);
    ASSERT(dst != nullptr);
    std::memcpy(dst, std::addressof(m_header.fs_header_hash[index]), sizeof(*dst));
}

void NcaReader::GetFsInfo(NcaHeader::FsInfo* dst, s32 index) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);
    ASSERT(dst != nullptr);
    std::memcpy(dst, std::addressof(m_header.fs_info[index]), sizeof(*dst));
}

uint64_t NcaReader::GetFsOffset(s32 index) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);
    return NcaHeader::SectorToByte(m_header.fs_info[index].start_sector);
}

uint64_t NcaReader::GetFsEndOffset(s32 index) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);
    return NcaHeader::SectorToByte(m_header.fs_info[index].end_sector);
}

uint64_t NcaReader::GetFsSize(s32 index) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);
    return NcaHeader::SectorToByte(m_header.fs_info[index].end_sector -
                                   m_header.fs_info[index].start_sector);
}

void NcaReader::GetEncryptedKey(void* dst, size_t size) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(dst != nullptr);
    ASSERT(size >= NcaHeader::EncryptedKeyAreaSize);

    std::memcpy(dst, m_header.encrypted_key_area.data(), NcaHeader::EncryptedKeyAreaSize);
}

bool NcaReader::IsSoftwareAesPrioritized() const {
    return m_is_software_aes_prioritized;
}

void NcaReader::PrioritizeSoftwareAes() {
    m_is_software_aes_prioritized = true;
}

bool NcaReader::IsAvailableSwKey() const {
    return m_is_available_sw_key;
}

void NcaReader::GetRawData(void* dst, size_t dst_size) const {
    ASSERT(m_body_storage != nullptr);
    ASSERT(dst != nullptr);
    ASSERT(dst_size >= sizeof(NcaHeader));

    std::memcpy(dst, std::addressof(m_header), sizeof(NcaHeader));
}

GetDecompressorFunction NcaReader::GetDecompressor() const {
    ASSERT(m_get_decompressor != nullptr);
    return m_get_decompressor;
}

Result NcaReader::ReadHeader(NcaFsHeader* dst, s32 index) const {
    ASSERT(dst != nullptr);
    ASSERT(0 <= index && index < NcaHeader::FsCountMax);

    const s64 offset = sizeof(NcaHeader) + sizeof(NcaFsHeader) * index;
    R_UNLESS(m_header_storage->ReadObject(dst, offset) == sizeof(*dst), ResultInvalidNcaHeader);

    R_SUCCEED();
}

bool NcaReader::GetHeaderSign1Valid() const {
    return m_is_header_sign1_signature_valid;
}

void NcaReader::GetHeaderSign2(void* dst, size_t size) const {
    ASSERT(dst != nullptr);
    ASSERT(size == NcaHeader::HeaderSignSize);

    std::memcpy(dst, m_header.header_sign_2.data(), size);
}

Result NcaFsHeaderReader::Initialize(const NcaReader& reader, s32 index) {
    // Reset ourselves to uninitialized.
    m_fs_index = -1;

    // Read the header.
    R_TRY(reader.ReadHeader(std::addressof(m_data), index));

    // Set our index.
    m_fs_index = index;
    R_SUCCEED();
}

void NcaFsHeaderReader::GetRawData(void* dst, size_t dst_size) const {
    ASSERT(this->IsInitialized());
    ASSERT(dst != nullptr);
    ASSERT(dst_size >= sizeof(NcaFsHeader));

    std::memcpy(dst, std::addressof(m_data), sizeof(NcaFsHeader));
}

NcaFsHeader::HashData& NcaFsHeaderReader::GetHashData() {
    ASSERT(this->IsInitialized());
    return m_data.hash_data;
}

const NcaFsHeader::HashData& NcaFsHeaderReader::GetHashData() const {
    ASSERT(this->IsInitialized());
    return m_data.hash_data;
}

u16 NcaFsHeaderReader::GetVersion() const {
    ASSERT(this->IsInitialized());
    return m_data.version;
}

s32 NcaFsHeaderReader::GetFsIndex() const {
    ASSERT(this->IsInitialized());
    return m_fs_index;
}

NcaFsHeader::FsType NcaFsHeaderReader::GetFsType() const {
    ASSERT(this->IsInitialized());
    return m_data.fs_type;
}

NcaFsHeader::HashType NcaFsHeaderReader::GetHashType() const {
    ASSERT(this->IsInitialized());
    return m_data.hash_type;
}

NcaFsHeader::EncryptionType NcaFsHeaderReader::GetEncryptionType() const {
    ASSERT(this->IsInitialized());
    return m_data.encryption_type;
}

NcaPatchInfo& NcaFsHeaderReader::GetPatchInfo() {
    ASSERT(this->IsInitialized());
    return m_data.patch_info;
}

const NcaPatchInfo& NcaFsHeaderReader::GetPatchInfo() const {
    ASSERT(this->IsInitialized());
    return m_data.patch_info;
}

const NcaAesCtrUpperIv NcaFsHeaderReader::GetAesCtrUpperIv() const {
    ASSERT(this->IsInitialized());
    return m_data.aes_ctr_upper_iv;
}

bool NcaFsHeaderReader::IsSkipLayerHashEncryption() const {
    ASSERT(this->IsInitialized());
    return m_data.IsSkipLayerHashEncryption();
}

Result NcaFsHeaderReader::GetHashTargetOffset(s64* out) const {
    ASSERT(out != nullptr);
    ASSERT(this->IsInitialized());

    R_RETURN(m_data.GetHashTargetOffset(out));
}

bool NcaFsHeaderReader::ExistsSparseLayer() const {
    ASSERT(this->IsInitialized());
    return m_data.sparse_info.generation != 0;
}

NcaSparseInfo& NcaFsHeaderReader::GetSparseInfo() {
    ASSERT(this->IsInitialized());
    return m_data.sparse_info;
}

const NcaSparseInfo& NcaFsHeaderReader::GetSparseInfo() const {
    ASSERT(this->IsInitialized());
    return m_data.sparse_info;
}

bool NcaFsHeaderReader::ExistsCompressionLayer() const {
    ASSERT(this->IsInitialized());
    return m_data.compression_info.bucket.offset != 0 && m_data.compression_info.bucket.size != 0;
}

NcaCompressionInfo& NcaFsHeaderReader::GetCompressionInfo() {
    ASSERT(this->IsInitialized());
    return m_data.compression_info;
}

const NcaCompressionInfo& NcaFsHeaderReader::GetCompressionInfo() const {
    ASSERT(this->IsInitialized());
    return m_data.compression_info;
}

bool NcaFsHeaderReader::ExistsPatchMetaHashLayer() const {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_data_info.size != 0 && this->GetPatchInfo().HasIndirectTable();
}

NcaMetaDataHashDataInfo& NcaFsHeaderReader::GetPatchMetaDataHashDataInfo() {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_data_info;
}

const NcaMetaDataHashDataInfo& NcaFsHeaderReader::GetPatchMetaDataHashDataInfo() const {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_data_info;
}

NcaFsHeader::MetaDataHashType NcaFsHeaderReader::GetPatchMetaHashType() const {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_type;
}

bool NcaFsHeaderReader::ExistsSparseMetaHashLayer() const {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_data_info.size != 0 && this->ExistsSparseLayer();
}

NcaMetaDataHashDataInfo& NcaFsHeaderReader::GetSparseMetaDataHashDataInfo() {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_data_info;
}

const NcaMetaDataHashDataInfo& NcaFsHeaderReader::GetSparseMetaDataHashDataInfo() const {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_data_info;
}

NcaFsHeader::MetaDataHashType NcaFsHeaderReader::GetSparseMetaHashType() const {
    ASSERT(this->IsInitialized());
    return m_data.meta_data_hash_type;
}

} // namespace FileSys
