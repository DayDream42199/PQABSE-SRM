#include "entities/SearchGateway.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <openssl/sha.h>
#include <oqs/oqs.h>
#include <stdexcept>

#include "pq_src/BlockchainClient.h"
#include "pq_src/TrustedAuthority.h"
#include "system/RuntimePaths.h"

namespace abse_zkp {
namespace {
constexpr std::int64_t kAllowedClockSkewSeconds = 300;
std::string quote_argument(const std::string& value) { return "\"" + value + "\""; }
std::string quote_path(const std::filesystem::path& path) { return quote_argument(path.string()); }
std::string run_command_capture(const std::string& command) {
    std::string output;
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) return output;
    char buffer[256];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) output += buffer;
    pclose(pipe);
    return output;
}
std::string make_nonce_key(int epoch, int nonce) { return std::to_string(epoch) + "|" + std::to_string(nonce); }
std::int64_t current_unix_timestamp() {
    using clock = std::chrono::system_clock;
    return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(clock::now().time_since_epoch()).count());
}
double elapsed_ms(const std::chrono::high_resolution_clock::time_point& start,
                  const std::chrono::high_resolution_clock::time_point& end) {
    return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - start).count();
}

std::array<unsigned char, 16> derive_reencrypted_file_nonce(const std::array<unsigned char, 16>& current_nonce,
                                                            const CloudRekeyState& rekey_state,
                                                            const std::string& bundle_label,
                                                            int target_epoch) {
    std::string input = rekey_state.re_encryption_key + "|" + rekey_state.revoked_user_gid + "|" +
                        bundle_label + "|" + std::to_string(target_epoch);
    input.append(reinterpret_cast<const char*>(current_nonce.data()), current_nonce.size());
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    std::array<unsigned char, 16> next_nonce{};
    std::copy(digest, digest + next_nonce.size(), next_nonce.begin());
    return next_nonce;
}
}

SearchGateway::SearchGateway(const IdentityAuthority& authority)
    : ia_public_key(authority.get_public_key()),
      ia_signature_algorithm(authority.get_signature_algorithm()),
      node_verify_script((WorkspaceRoot() / "zk" / "scripts" / "verify_membership.mjs").string()),
      used_nonces_path(WorkspaceRoot() / "zk" / "build" / "runtime_cpp" / "used_nonces.txt") {
    load_used_nonces();
    prune_used_nonces_for_current_epoch();
}

std::filesystem::path SearchGateway::SearchIndexPath(int epoch) const {
    return SearchArtifactRoot() / ("bitmap_index_epoch_" + std::to_string(epoch) + ".bin");
}

void SearchGateway::load_used_nonces() {
    used_nonces.clear();
    std::filesystem::create_directories(used_nonces_path.parent_path());
    std::ifstream input(used_nonces_path);
    std::string line;
    while (std::getline(input, line)) if (!line.empty()) used_nonces.insert(line);
}

void SearchGateway::persist_used_nonces() const {
    std::filesystem::create_directories(used_nonces_path.parent_path());
    std::ofstream output(used_nonces_path, std::ios::trunc);
    for (const auto& key : used_nonces) output << key << "\n";
}

void SearchGateway::prune_used_nonces_for_current_epoch() {
    Blockchain.sync_from_chain();
    std::unordered_set<std::string> filtered;
    const std::string prefix = std::to_string(Blockchain.current_state.epoch) + "|";
    for (const auto& key : used_nonces) if (key.rfind(prefix, 0) == 0) filtered.insert(key);
    if (filtered.size() != used_nonces.size()) {
        used_nonces = std::move(filtered);
        persist_used_nonces();
    }
}

bool SearchGateway::VerifyAuthToken(const AuthToken& token) {
    Blockchain.sync_from_chain();
    OQS_SIG* verifier = OQS_SIG_new(ia_signature_algorithm.c_str());
    if (verifier == nullptr) return false;
    std::string attribute_csv;
    for (std::size_t index = 0; index < token.attributes.size(); ++index) {
        if (index > 0) {
            attribute_csv += ",";
        }
        attribute_csv += token.attributes[index];
    }
    const std::string payload = token.user_gid + "|" + token.zk_id + "|" +
                                std::to_string(token.leaf_index) + "|" +
                                std::to_string(token.issued_tag.epoch) + "|" +
                                token.issued_tag.revocation_root + "|" +
                                token.registration_root + "|" +
                                std::to_string(token.nonce) + "|" +
                                std::to_string(token.issued_at_unix) + "|" +
                                attribute_csv;
    const OQS_STATUS signature_ok = OQS_SIG_verify(verifier,
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size(),
        token.signature.data(), token.signature.size(), ia_public_key.data());
    OQS_SIG_free(verifier);
    if (signature_ok != OQS_SUCCESS) return false;
    if (token.issued_tag.epoch != Blockchain.current_state.epoch || token.issued_tag.revocation_root != Blockchain.current_state.revocation_root) return false;
    if (token.public_file_path.empty() || token.proof_file_path.empty()) return false;
    const std::string nonce_key = make_nonce_key(token.issued_tag.epoch, token.nonce);
    if (used_nonces.find(nonce_key) != used_nonces.end()) return false;
    if (std::llabs(current_unix_timestamp() - token.issued_at_unix) > kAllowedClockSkewSeconds) return false;
    const std::string verify_command = "node " + quote_path(node_verify_script) + " " +
        quote_argument(token.public_file_path) + " " +
        quote_argument(token.proof_file_path) + " " +
        quote_argument(BlockchainClient::hex_bytes32_to_decimal(token.registration_root)) + " " +
        quote_argument(BlockchainClient::hex_bytes32_to_decimal(token.issued_tag.revocation_root)) + " " +
        quote_argument(std::to_string(token.nonce)) + " " +
        quote_argument(std::to_string(token.issued_at_unix)) + " 2>&1";
    const auto start = std::chrono::high_resolution_clock::now();
    const std::string verify_output = run_command_capture(verify_command);
    const auto end = std::chrono::high_resolution_clock::now();
    last_verify_ms_ = elapsed_ms(start, end);
    if (verify_output.find("OK!") == std::string::npos) return false;
    used_nonces.insert(nonce_key);
    persist_used_nonces();
    return true;
}

bool SearchGateway::authorize_epoch_access(const UserRecord& user_record,
                                           const std::string& update_token,
                                           const CloudRekeyState& rekey_state) const {
    if (user_record.user_gid.empty() || user_record.is_revoked) {
        return false;
    }
    if (Blockchain.current_state.epoch == 0 || rekey_state.update_token_seed.empty() ||
        rekey_state.epoch != Blockchain.current_state.epoch) {
        return true;
    }
    TrustedAuthority ta;
    std::string expected_token;
    if (!ta.generate_update_token_for_user(user_record,
                                           Blockchain.current_state.epoch,
                                           rekey_state.update_token_seed,
                                           expected_token)) {
        return false;
    }
    return !update_token.empty() && update_token == expected_token;
}

bool SearchGateway::apply_lazy_reencryption(const SystemParams& params,
                                            StoredBundleRecord& bundle_record,
                                            CiphertextBundle& bundle,
                                            const CloudRekeyState& rekey_state) const {
    if (bundle_record.version_tag.epoch == Blockchain.current_state.epoch) return false;
    if (rekey_state.re_encryption_key.empty() || rekey_state.epoch != Blockchain.current_state.epoch) {
        throw std::runtime_error("Ciphertext is stale but no valid re-encryption key is available");
    }
    bundle.file_nonce = derive_reencrypted_file_nonce(bundle.file_nonce,
                                                      rekey_state,
                                                      bundle_record.bundle_label,
                                                      Blockchain.current_state.epoch);
    ReEncryptCiphertextBundle(params, bundle, "epoch-" + std::to_string(Blockchain.current_state.epoch),
                              rekey_state.re_encryption_key, rekey_state.update_token_seed);
    bundle.secure_index = BuildSecureIndex(params, bundle.keyword_set, bundle.file_nonce);
    bundle_record.version_tag = Blockchain.current_state;
    bundle_record.is_reencrypted = true;
    if (!SaveCiphertextBundle(params, bundle, bundle_record.bundle_path) ||
        !SaveStoredBundleRecord(bundle_record)) {
        throw std::runtime_error("Failed to persist lazy re-encrypted bundle state");
    }
    std::error_code ignored;
    std::filesystem::remove(SearchIndexPath(Blockchain.current_state.epoch), ignored);
    search_index_cache_valid_ = false;
    return true;
}

SearchOptimizationLayer SearchGateway::BuildSearchIndex(const SystemParams& params) const {
    const auto build_start = std::chrono::high_resolution_clock::now();
    const int epoch = Blockchain.current_state.epoch;
    const auto index_path = SearchIndexPath(epoch);
    const auto stored_labels = ListStoredBundleLabels();
    if (search_index_cache_valid_ && cached_search_index_epoch_ == epoch &&
        cached_search_index_labels_ == stored_labels) {
        last_search_index_cache_hit_ = true;
        last_index_prepare_ms_ = elapsed_ms(build_start, std::chrono::high_resolution_clock::now());
        return cached_search_index_;
    }

    last_search_index_cache_hit_ = false;
    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(epoch, epoch_bitmap_key)) {
        throw std::runtime_error("Failed to derive epoch bitmap key");
    }
    SearchOptimizationLayer index;
    if (SearchOptimizationLayer::LoadFromFile(index_path, index) && index.KnownLabels() == stored_labels) {
        cached_search_index_ = index;
        cached_search_index_epoch_ = epoch;
        cached_search_index_labels_ = stored_labels;
        search_index_cache_valid_ = true;
        last_index_prepare_ms_ = elapsed_ms(build_start, std::chrono::high_resolution_clock::now());
        return cached_search_index_;
    }

    SearchOptimizationLayer rebuilt;
    for (const auto& label : stored_labels) {
        StoredBundleRecord record;
        if (!LoadStoredBundleRecord(label, record)) {
            continue;
        }
        CiphertextBundle bundle;
        if (!LoadCiphertextBundle(params, bundle, record.bundle_path)) {
            continue;
        }
        rebuilt.ProcessNewUpload(label, bundle.secure_index, epoch, epoch_bitmap_key);
    }
    rebuilt.OptimizeAllBitmaps();
    rebuilt.SaveToFile(index_path);
    cached_search_index_ = rebuilt;
    cached_search_index_epoch_ = epoch;
    cached_search_index_labels_ = stored_labels;
    search_index_cache_valid_ = true;
    last_index_prepare_ms_ = elapsed_ms(build_start, std::chrono::high_resolution_clock::now());
    return cached_search_index_;
}

bool SearchGateway::SearchAndRetrieve(const SystemParams& params,
                                      const UserSecretKey& user_key,
                                      const UserRecord& user_record,
                                      const std::string& update_token,
                                      const std::vector<std::string>& query_keywords,
                                      const std::string& preferred_label,
                                      const CloudRekeyState& rekey_state,
                                      StoredBundleRecord& bundle_record,
                                      CiphertextBundle& bundle,
                                      SearchResult& result) {
    last_candidate_prune_ms_ = 0.0;
    last_retrieve_decrypt_ms_ = 0.0;
    if (user_key.epoch != Blockchain.current_state.epoch) {
        result = {};
        return false;
    }
    if (!rekey_state.update_token_seed.empty() && user_key.update_seed != rekey_state.update_token_seed) {
        result = {};
        return false;
    }
    if (!authorize_epoch_access(user_record, update_token, rekey_state)) {
        result = {};
        return false;
    }
    SearchTrapdoor shortlist_trapdoor;
    std::array<unsigned char, 16> global_nonce{};
    TrapGen(params, user_key, global_nonce, user_key.gid + "__search", query_keywords, shortlist_trapdoor);
    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(Blockchain.current_state.epoch, epoch_bitmap_key)) {
        throw std::runtime_error("Failed to derive epoch bitmap key");
    }

    const auto prune_start = std::chrono::high_resolution_clock::now();
    const auto search_index = BuildSearchIndex(params);
    last_candidate_labels_ = search_index.ResolveLabels(
        search_index.ExecuteAdaptiveSearch(
            BuildEpochBitmapKeys(shortlist_trapdoor.keyword_tokens, Blockchain.current_state.epoch, epoch_bitmap_key)));
    last_candidate_prune_ms_ = elapsed_ms(prune_start, std::chrono::high_resolution_clock::now());

    if (!preferred_label.empty()) {
        const bool preferred_present = std::find(last_candidate_labels_.begin(), last_candidate_labels_.end(), preferred_label) !=
                                       last_candidate_labels_.end();
        if (!preferred_present) {
            result = {};
            result.keyword_match = false;
            return false;
        }
        last_candidate_labels_ = {preferred_label};
    }

    for (const auto& label : last_candidate_labels_) {
        const auto retrieve_start = std::chrono::high_resolution_clock::now();
        StoredBundleRecord candidate_record;
        if (!LoadStoredBundleRecord(label, candidate_record)) {
            continue;
        }
        CiphertextBundle candidate_bundle;
        if (!LoadCiphertextBundle(params, candidate_bundle, candidate_record.bundle_path)) {
            continue;
        }

        apply_lazy_reencryption(params, candidate_record, candidate_bundle, rekey_state);

        SearchTrapdoor retrieve_trapdoor;
        TrapGen(params, user_key, candidate_bundle.file_nonce, user_key.gid + "__" + candidate_record.bundle_label,
                query_keywords, retrieve_trapdoor);

        SearchResult candidate_result;
        if (!RetrieveAndDecrypt(params, user_key, candidate_bundle, retrieve_trapdoor, candidate_result)) {
            continue;
        }

        last_retrieve_decrypt_ms_ = elapsed_ms(retrieve_start, std::chrono::high_resolution_clock::now());
        bundle_record = std::move(candidate_record);
        bundle = std::move(candidate_bundle);
        result = std::move(candidate_result);
        return true;
    }

    if (!last_candidate_labels_.empty()) {
        last_retrieve_decrypt_ms_ = 0.0;
    }
    result = {};
    result.keyword_match = !last_candidate_labels_.empty();
    return false;
}

double SearchGateway::last_verify_time_ms() const { return last_verify_ms_; }
const std::vector<std::string>& SearchGateway::last_candidate_labels() const { return last_candidate_labels_; }
double SearchGateway::last_index_prepare_time_ms() const { return last_index_prepare_ms_; }
double SearchGateway::last_candidate_prune_time_ms() const { return last_candidate_prune_ms_; }
double SearchGateway::last_retrieve_decrypt_time_ms() const { return last_retrieve_decrypt_ms_; }
bool SearchGateway::last_search_index_cache_hit() const { return last_search_index_cache_hit_; }

}  // namespace abse_zkp
