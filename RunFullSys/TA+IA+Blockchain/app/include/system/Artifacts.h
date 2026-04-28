#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "phase2_keygen.h"
#include "phase3_encrypt.h"
#include "pq_src/Blockchain.h"

namespace abse_zkp {

struct UserCredentialRecord {
    std::string gid;
    int identity_secret = 0;
    int local_epoch = 0;
    std::string user_key_path;
    std::vector<std::string> attributes;
};

struct StoredBundleRecord {
    std::string bundle_label;
    std::string bundle_label_token;
    std::string bundle_path;
    std::string data_owner_gid;
    VersionTag version_tag;
    bool is_reencrypted = false;
};

struct CloudRekeyState {
    int epoch = 0;
    std::string re_encryption_key;
    std::string update_token_seed;
    std::string revoked_user_gid;
};

std::filesystem::path UserCredentialPath(const std::string& gid);
std::filesystem::path UserSecretKeyPath(const std::string& gid);
std::filesystem::path BundleBinaryPath(const std::string& label);
std::filesystem::path BundleMetaPath(const std::string& label);
std::filesystem::path CloudRekeyStatePath();
std::filesystem::path UpdateTokenPath(const std::string& gid, int epoch);

bool SaveUserCredentialRecord(const UserCredentialRecord& record);
bool LoadUserCredentialRecord(const std::string& gid, UserCredentialRecord& record);
bool SaveStoredBundleRecord(const StoredBundleRecord& record);
bool LoadStoredBundleRecord(const std::string& label, StoredBundleRecord& record);
std::vector<std::string> ListStoredBundleLabels();
bool SaveCloudRekeyState(const CloudRekeyState& state);
bool LoadCloudRekeyState(CloudRekeyState& state);
bool WriteTextFile(const std::filesystem::path& path, const std::string& content);
bool ReadTextFile(const std::filesystem::path& path, std::string& content);

}  // namespace abse_zkp
