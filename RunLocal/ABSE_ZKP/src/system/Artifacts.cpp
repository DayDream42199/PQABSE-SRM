#include "system/Artifacts.h"
#include "system/RuntimePaths.h"

#include <algorithm>
#include <fstream>
#include <map>
#include <stdexcept>

namespace abse_zkp {
namespace {
std::map<std::string, std::string> LoadKeyValues(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        values[line.substr(0, pos)] = line.substr(pos + 1);
    }
    return values;
}
std::string JoinStrings(const std::vector<std::string>& values) {
    std::string joined;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) joined += ',';
        joined += values[i];
    }
    return joined;
}
std::vector<std::string> SplitStrings(const std::string& value) {
    std::vector<std::string> output;
    std::string current;
    for (char ch : value) {
        if (ch == ',') {
            if (!current.empty()) {
                output.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty()) output.push_back(current);
    return output;
}
std::string RequireValue(const std::map<std::string, std::string>& values, const std::string& key) {
    const auto it = values.find(key);
    if (it == values.end()) {
        throw std::runtime_error("Missing required artifact field: " + key);
    }
    return it->second;
}
}
std::filesystem::path UserCredentialPath(const std::string& gid) { return UserArtifactRoot() / (gid + ".cred"); }
std::filesystem::path UserSecretKeyPath(const std::string& gid) { return UserArtifactRoot() / (gid + "_userkey.bin"); }
std::filesystem::path BundleBinaryPath(const std::string& label) { return CiphertextArtifactRoot() / (label + "_bundle.bin"); }
std::filesystem::path BundleMetaPath(const std::string& label) { return CiphertextArtifactRoot() / (label + "_bundle.meta"); }
std::filesystem::path CloudRekeyStatePath() { return CloudArtifactRoot() / "rekey_state.txt"; }
std::filesystem::path UpdateTokenPath(const std::string& gid, int epoch) { return UpdateTokenRoot() / (gid + "_epoch_" + std::to_string(epoch) + ".token"); }

bool SaveUserCredentialRecord(const UserCredentialRecord& record) {
    EnsureRuntimeDirectories();
    std::ofstream output(UserCredentialPath(record.gid), std::ios::trunc);
    if (!output.is_open()) return false;
    output << "gid=" << record.gid << '\n';
    output << "identity_secret=" << record.identity_secret << '\n';
    output << "local_epoch=" << record.local_epoch << '\n';
    output << "user_key_path=" << record.user_key_path << '\n';
    output << "attributes=" << JoinStrings(record.attributes) << '\n';
    return static_cast<bool>(output);
}

bool LoadUserCredentialRecord(const std::string& gid, UserCredentialRecord& record) {
    const auto values = LoadKeyValues(UserCredentialPath(gid));
    if (values.empty()) return false;
    record.gid = RequireValue(values, "gid");
    record.identity_secret = std::stoi(RequireValue(values, "identity_secret"));
    record.local_epoch = std::stoi(RequireValue(values, "local_epoch"));
    record.user_key_path = RequireValue(values, "user_key_path");
    if (const auto it = values.find("attributes"); it != values.end()) record.attributes = SplitStrings(it->second);
    return true;
}

bool SaveStoredBundleRecord(const StoredBundleRecord& record) {
    EnsureRuntimeDirectories();
    std::ofstream output(BundleMetaPath(record.bundle_label), std::ios::trunc);
    if (!output.is_open()) return false;
    output << "bundle_label=" << record.bundle_label << '\n';
    output << "bundle_path=" << record.bundle_path << '\n';
    output << "data_owner_gid=" << record.data_owner_gid << '\n';
    output << "epoch=" << record.version_tag.epoch << '\n';
    output << "registration_root=" << record.version_tag.registration_root << '\n';
    output << "revocation_root=" << record.version_tag.revocation_root << '\n';
    output << "is_reencrypted=" << (record.is_reencrypted ? 1 : 0) << '\n';
    return static_cast<bool>(output);
}

bool LoadStoredBundleRecord(const std::string& label, StoredBundleRecord& record) {
    const auto values = LoadKeyValues(BundleMetaPath(label));
    if (values.empty()) return false;
    record.bundle_label = RequireValue(values, "bundle_label");
    record.bundle_path = RequireValue(values, "bundle_path");
    if (const auto it = values.find("data_owner_gid"); it != values.end()) {
        record.data_owner_gid = it->second;
    } else {
        record.data_owner_gid = RequireValue(values, "owner_gid");
    }
    record.version_tag.epoch = std::stoi(RequireValue(values, "epoch"));
    record.version_tag.registration_root = RequireValue(values, "registration_root");
    record.version_tag.revocation_root = RequireValue(values, "revocation_root");
    record.is_reencrypted = std::stoi(RequireValue(values, "is_reencrypted")) != 0;
    return true;
}

std::vector<std::string> ListStoredBundleLabels() {
    std::vector<std::string> labels;
    const auto root = CiphertextArtifactRoot();
    if (!std::filesystem::exists(root)) {
        return labels;
    }

    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto path = entry.path();
        if (path.extension() != ".meta") {
            continue;
        }
        const std::string filename = path.filename().string();
        const std::string suffix = "_bundle.meta";
        if (filename.size() <= suffix.size() || filename.substr(filename.size() - suffix.size()) != suffix) {
            continue;
        }
        labels.push_back(filename.substr(0, filename.size() - suffix.size()));
    }

    std::sort(labels.begin(), labels.end());
    return labels;
}

bool SaveCloudRekeyState(const CloudRekeyState& state) {
    EnsureRuntimeDirectories();
    std::ofstream output(CloudRekeyStatePath(), std::ios::trunc);
    if (!output.is_open()) return false;
    output << "epoch=" << state.epoch << '\n';
    output << "re_encryption_key=" << state.re_encryption_key << '\n';
    output << "update_token_seed=" << state.update_token_seed << '\n';
    output << "revoked_user_gid=" << state.revoked_user_gid << '\n';
    return static_cast<bool>(output);
}

bool LoadCloudRekeyState(CloudRekeyState& state) {
    const auto values = LoadKeyValues(CloudRekeyStatePath());
    if (values.empty()) return false;
    state.epoch = std::stoi(RequireValue(values, "epoch"));
    state.re_encryption_key = RequireValue(values, "re_encryption_key");
    if (const auto it = values.find("update_token_seed"); it != values.end()) state.update_token_seed = it->second;
    if (const auto it = values.find("revoked_user_gid"); it != values.end()) state.revoked_user_gid = it->second;
    return true;
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::trunc);
    output << content;
    return static_cast<bool>(output);
}

bool ReadTextFile(const std::filesystem::path& path, std::string& content) {
    std::ifstream input(path);
    if (!input.is_open()) return false;
    content.assign((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return true;
}

}  // namespace abse_zkp
