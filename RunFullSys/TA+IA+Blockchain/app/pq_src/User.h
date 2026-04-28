#pragma once

#include <string>
#include "IdentityAuthority.h"

class User {
private:
    std::string gid;
    int identity_secret;
    bool has_identity_secret;
    AuthToken auth_token;

public:
    explicit User(std::string gid_value, int known_identity_secret = 0, bool has_secret = false);

    const std::string& get_gid() const;
    const AuthToken& get_auth_token() const;
    int get_identity_secret() const;
    void set_identity_secret(int new_identity_secret);

    bool register_with_authority(IdentityAuthority& authority);
    bool request_authentication(IdentityAuthority& authority);
    bool request_zkp_authentication(IdentityAuthority& authority);
    bool request_zkp_authentication(IdentityAuthority& authority, const std::vector<std::string>& attributes);
    bool request_registration_auth_path(const IdentityAuthority& authority, std::vector<MerkleProofNode>& auth_path) const;
};
