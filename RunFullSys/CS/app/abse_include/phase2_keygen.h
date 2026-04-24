#ifndef PHASE2_KEYGEN_H
#define PHASE2_KEYGEN_H

#include "phase1_setup.h"

#include <string>
#include <vector>

struct UserSecretKey {
    std::string gid;
    std::vector<std::string> attributes;
    int epoch = 0;
    std::string update_seed;
    TrapdoorElement target_u;
    TrapdoorMatrix preimage;
};

TrapdoorElement EncodeIdentityAndAttributes(const SystemParams& params, const std::string& gid,
                                            const std::vector<std::string>& attributes,
                                            int epoch = 0,
                                            const std::string& update_seed = "");
void KeyGen(const SystemParams& params, const PK& pk, const MSK& msk, const std::string& gid,
            const std::vector<std::string>& attributes, UserSecretKey& user_sk,
            int epoch = 0,
            const std::string& update_seed = "");
bool VerifyUserSecretKey(const PK& pk, const UserSecretKey& user_sk);
bool SaveUserSecretKey(const SystemParams& params, const UserSecretKey& user_sk, const std::string& path);
bool LoadUserSecretKey(const SystemParams& params, UserSecretKey& user_sk, const std::string& path);

#endif
