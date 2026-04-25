#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "phase3_encrypt.h"

namespace abse_zkp {

struct NitroTeeOptions {
    std::uint32_t enclave_cid = 16;
    std::uint32_t port = 5005;
    int timeout_ms = 30000;
};

class NitroTeeClient {
public:
    void CreateCiphertextBundle(const SystemParams& params,
                                const PK& pk,
                                const MSK& msk,
                                const std::string& bundle_label,
                                const std::string& plaintext,
                                const std::vector<std::string>& keywords,
                                const LogicalPolicy& logical_policy,
                                const std::string& version_tag,
                                CiphertextBundle& bundle,
                                const NitroTeeOptions& options) const;
};

}  // namespace abse_zkp
