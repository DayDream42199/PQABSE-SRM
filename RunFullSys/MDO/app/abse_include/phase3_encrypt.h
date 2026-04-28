#ifndef PHASE3_ENCRYPT_H
#define PHASE3_ENCRYPT_H

#include "phase1_setup.h"
#include "phase2_keygen.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

enum class PolicyKind {
    Attribute,
    And,
    Or,
    Threshold,
};

struct LogicalPolicy {
    PolicyKind kind;
    size_t threshold;
    std::string attribute;
    std::vector<LogicalPolicy> children;
};

struct AccessPolicy {
    std::vector<std::vector<int64_t>> matrix;
    std::vector<std::string> rho;
    std::string descriptor;
    bool is_summary;
};

struct CiphertextKey {
    TrapdoorElement header_u;
    TrapdoorElement policy_tag;
    TrapdoorElement epoch_tag;
    std::string reencryption_tag;
    std::array<unsigned char, 32> update_seed_commitment;
    std::array<unsigned char, 32> encrypted_session_key;
    AccessPolicy policy;
};

struct CiphertextBundle {
    std::string bundle_label;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ctdata;
    std::vector<unsigned char> auth_tag;
    CiphertextKey ctk;
    std::vector<TrapdoorElement> secure_index;
    std::vector<std::string> keyword_set;
    std::array<unsigned char, 16> file_nonce;
    std::string version_tag;
    LogicalPolicy logical_policy;
    AccessPolicy policy;
    bool ctdata_verified;
};

LogicalPolicy MakeAttributePolicy(const std::string& attribute);
LogicalPolicy MakeAndPolicy(const std::vector<std::string>& attributes);
LogicalPolicy MakeAndPolicy(const std::vector<LogicalPolicy>& children);
LogicalPolicy MakeOrPolicy(const std::vector<std::string>& attributes);
LogicalPolicy MakeOrPolicy(const std::vector<LogicalPolicy>& children);
LogicalPolicy MakeThresholdPolicy(size_t threshold, const std::vector<std::string>& attributes);
LogicalPolicy MakeThresholdPolicy(size_t threshold, const std::vector<LogicalPolicy>& children);
AccessPolicy BuildAccessPolicy(const LogicalPolicy& logical_policy);
std::string DescribeLogicalPolicy(const LogicalPolicy& logical_policy);
TrapdoorElement EncodeAccessPolicy(const SystemParams& params, const AccessPolicy& policy);
TrapdoorElement EncodeKeywordToken(const SystemParams& params, const std::string& keyword,
                                   const std::array<unsigned char, 16>& file_nonce);
std::array<unsigned char, 32> GenerateSessionKey();
bool EncryptData(const std::array<unsigned char, 32>& session_key, const std::string& plaintext,
                 std::vector<unsigned char>& nonce, std::vector<unsigned char>& ciphertext,
                 std::vector<unsigned char>& auth_tag);
bool DecryptData(const std::array<unsigned char, 32>& session_key, const std::vector<unsigned char>& nonce,
                 const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& auth_tag,
                 std::string& plaintext_out);
void EncABSE(const SystemParams& params, const PK& pk, const std::array<unsigned char, 32>& session_key,
             const AccessPolicy& policy, const std::string& version_tag,
             const std::array<unsigned char, 16>& file_nonce,
             const std::string& re_encryption_material,
             const std::string& user_update_material,
             CiphertextKey& ciphertext);
bool DecABSE(const SystemParams& params, const UserSecretKey& user_sk,
             const LogicalPolicy& logical_policy, const CiphertextKey& ciphertext,
             std::array<unsigned char, 32>& session_key_out);
void ReEncryptCiphertextBundle(const SystemParams& params, CiphertextBundle& bundle,
                             const std::string& next_version_tag,
                             const std::string& re_encryption_material,
                             const std::string& user_update_material);
bool PolicySatisfied(const std::vector<std::string>& user_attributes, const LogicalPolicy& logical_policy);
std::vector<TrapdoorElement> BuildSecureIndex(const SystemParams& params,
                                              const std::vector<std::string>& keywords,
                                              const std::array<unsigned char, 16>& file_nonce);
void AssembleCiphertextBundle(const SystemParams& params, const PK& pk, const std::string& bundle_label,
                              const std::string& plaintext, const std::vector<std::string>& keywords,
                              const LogicalPolicy& logical_policy, const std::string& version_tag,
                              CiphertextBundle& bundle, double* mobile_encrypt_ms = nullptr);
bool SaveCiphertextBundle(const SystemParams& params, const CiphertextBundle& bundle, const std::string& path);
bool LoadCiphertextBundle(const SystemParams& params, CiphertextBundle& bundle, const std::string& path);

#endif
