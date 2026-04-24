#pragma once

#include <filesystem>
#include <string>
#include <vector>
#include "IdentityAuthority.h"

class TrustedAuthority {
private:
    std::filesystem::path artifact_directory;
    std::vector<std::vector<int>> master_secret_trapdoor;

    bool load_master_secret_trapdoor(const std::string& trapdoor_path);
    std::string real_poseidon_hash(const std::string& input) const;

public:
    explicit TrustedAuthority(const std::filesystem::path& artifact_dir = "runtime/abse");

    bool generate_re_encryption_material(const UserRecord& revoked_user,
                                         int new_epoch,
                                         ReEncryptionMaterial& material) const;
    bool generate_update_token_for_user(const UserRecord& user,
                                        int new_epoch,
                                        std::string& update_token) const;
    bool generate_update_token_for_user(const UserRecord& user,
                                        int new_epoch,
                                        const std::string& update_token_seed,
                                        std::string& update_token) const;
    bool derive_bitmap_epoch_key(int epoch, std::string& epoch_bitmap_key) const;
};
