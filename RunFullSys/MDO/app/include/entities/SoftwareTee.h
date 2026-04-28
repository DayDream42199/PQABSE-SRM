#pragma once

#include <string>
#include <vector>

#include "phase2_keygen.h"
#include "phase3_encrypt.h"

namespace abse_zkp {

class SoftwareTee {
public:
    void GenerateUserKey(const SystemParams& params,
                         const PK& pk,
                         const MSK& msk,
                         const std::string& gid,
                         const std::vector<std::string>& attributes,
                         UserSecretKey& user_key,
                         int epoch = 0,
                         const std::string& update_seed = "") const;

    void CreateCiphertextBundle(const SystemParams& params,
                                const PK& pk,
                                const std::string& bundle_label,
                                const std::string& plaintext,
                                const std::vector<std::string>& keywords,
                                const LogicalPolicy& logical_policy,
                                const std::string& version_tag,
                                CiphertextBundle& bundle,
                                double* mobile_encrypt_ms = nullptr) const;
};

LogicalPolicy BuildLogicalPolicyFromParts(const std::string& policy_type,
                                          const std::vector<std::string>& policy_attrs,
                                          std::size_t threshold);
LogicalPolicy BuildLogicalPolicyFromExpression(const std::string& expression);

}  // namespace abse_zkp
