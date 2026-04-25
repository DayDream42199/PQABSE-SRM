#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "phase2_keygen.h"
#include "phase3_encrypt.h"

namespace abse_zkp {

struct NitroTeeOptions {
    std::uint32_t enclave_cid = 16;
    std::uint32_t port = 5005;
    int timeout_ms = 30000;
};

class NitroTeeClient {
public:
    void GenerateUserKey(const SystemParams& params,
                         const PK& pk,
                         const MSK& msk,
                         const std::string& gid,
                         const std::vector<std::string>& attributes,
                         UserSecretKey& user_key,
                         int epoch,
                         const std::string& update_seed,
                         const NitroTeeOptions& options) const;
};

}  // namespace abse_zkp
