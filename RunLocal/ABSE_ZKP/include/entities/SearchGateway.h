#pragma once

#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

#include "phase2_keygen.h"
#include "phase3_encrypt.h"
#include "phase4_search.h"
#include "pq_src/IdentityAuthority.h"
#include "search_include/Search.h"
#include "system/Artifacts.h"

namespace abse_zkp {

class SearchGateway {
public:
    explicit SearchGateway(const IdentityAuthority& authority);

    bool VerifyAuthToken(const AuthToken& token);
    bool SearchAndRetrieve(const SystemParams& params,
                           const UserSecretKey& user_key,
                           const UserRecord& user_record,
                           const std::string& update_token,
                           const std::vector<std::string>& query_keywords,
                           const std::string& preferred_label,
                           const CloudRekeyState& rekey_state,
                           StoredBundleRecord& bundle_record,
                           CiphertextBundle& bundle,
                           SearchResult& result);
    double last_verify_time_ms() const;
    const std::vector<std::string>& last_candidate_labels() const;
    double last_index_prepare_time_ms() const;
    double last_candidate_prune_time_ms() const;
    double last_retrieve_decrypt_time_ms() const;
    bool last_search_index_cache_hit() const;

private:
    std::vector<uint8_t> ia_public_key;
    std::string ia_signature_algorithm;
    std::string node_verify_script;
    std::filesystem::path used_nonces_path;
    std::unordered_set<std::string> used_nonces;
    double last_verify_ms_ = 0.0;
    mutable double last_index_prepare_ms_ = 0.0;
    double last_candidate_prune_ms_ = 0.0;
    double last_retrieve_decrypt_ms_ = 0.0;
    mutable bool last_search_index_cache_hit_ = false;
    std::vector<std::string> last_candidate_labels_;
    mutable bool search_index_cache_valid_ = false;
    mutable int cached_search_index_epoch_ = -1;
    mutable std::vector<std::string> cached_search_index_labels_;
    mutable SearchOptimizationLayer cached_search_index_;

    void load_used_nonces();
    void persist_used_nonces() const;
    void prune_used_nonces_for_current_epoch();
    bool authorize_epoch_access(const UserRecord& user_record,
                                const std::string& update_token,
                                const CloudRekeyState& rekey_state) const;
    bool apply_lazy_reencryption(const SystemParams& params,
                                 StoredBundleRecord& bundle_record,
                                 CiphertextBundle& bundle,
                                 const CloudRekeyState& rekey_state) const;
    SearchOptimizationLayer BuildSearchIndex(const SystemParams& params) const;
    std::filesystem::path SearchIndexPath(int epoch) const;
};

}  // namespace abse_zkp
