#include <algorithm>
#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>

#include "entities/SearchGateway.h"
#include "phase1_setup.h"
#include "phase4_search.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "search_include/Search.h"
#include "system/Artifacts.h"
#include "system/AuthTokenIO.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"

namespace {

using namespace abse_zkp;

std::array<unsigned char, 32> HashUpdateMaterial(const std::string& updateMaterial) {
    std::array<unsigned char, 32> digest{};
    if (updateMaterial.empty()) {
        return digest;
    }
    SHA256(reinterpret_cast<const unsigned char*>(updateMaterial.data()), updateMaterial.size(), digest.data());
    return digest;
}

std::array<unsigned char, 16> DeriveReencryptedFileNonce(const std::array<unsigned char, 16>& currentNonce,
                                                         const CloudRekeyState& rekeyState,
                                                         const std::string& bundleLabel,
                                                         int targetEpoch) {
    std::string input = rekeyState.re_encryption_key + "|" + rekeyState.revoked_user_gid + "|" +
                        bundleLabel + "|" + std::to_string(targetEpoch);
    input.append(reinterpret_cast<const char*>(currentNonce.data()), currentNonce.size());
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    std::array<unsigned char, 16> nextNonce{};
    std::copy(digest, digest + nextNonce.size(), nextNonce.begin());
    return nextNonce;
}

bool NeedsLazyReencryption(const StoredBundleRecord& record,
                           const CiphertextBundle& bundle,
                           const CloudRekeyState& rekeyState,
                           int currentEpoch) {
    if (record.version_tag.epoch != currentEpoch) {
        return true;
    }
    if (currentEpoch == 0 || rekeyState.update_token_seed.empty()) {
        return false;
    }
    return bundle.ctk.update_seed_commitment != HashUpdateMaterial(rekeyState.update_token_seed);
}

std::filesystem::path SearchIndexPathForEpoch(int epoch) {
    return SearchArtifactRoot() / ("bitmap_index_epoch_" + std::to_string(epoch) + ".bin");
}

SearchOptimizationLayer LoadOrBuildSearchIndex(const SystemParams& params, int epoch) {
    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(epoch, epoch_bitmap_key)) {
        throw std::runtime_error("Failed to derive epoch bitmap key");
    }

    const auto index_path = SearchIndexPathForEpoch(epoch);
    SearchOptimizationLayer index;
    if (SearchOptimizationLayer::LoadFromFile(index_path, index)) {
        return index;
    }

    SearchOptimizationLayer rebuilt;
    for (const auto& label : ListStoredBundleLabels()) {
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
    return rebuilt;
}

std::size_t DefaultMinMatchCount(const SearchTrapdoor& trapdoor) {
    if (trapdoor.query_keywords.empty()) {
        return 0;
    }
    if (trapdoor.query_keywords.size() < 3) {
        return 1;
    }
    return 2;
}

struct RankedBundleMatch {
    std::string label;
    std::size_t matched_count = 0;
    StoredBundleRecord record;
};

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);
    const auto candidate_timing_out = cli.Get("--candidate-timing-out");
    const bool skip_auth_verification = cli.HasFlag("--skip-auth-verification");
    const std::size_t max_results = static_cast<std::size_t>(std::stoul(cli.Get("--max-results", "10")));

    const auto request_dir = std::filesystem::path(cli.Require("--request-dir"));
    const auto response_dir = std::filesystem::path(cli.Require("--response-dir"));
    const auto verification_key_override = request_dir / "verification_key.json";

    if (std::filesystem::exists(verification_key_override)) {
#ifdef _WIN32
        _putenv_s("PQ_ABSE_VERIFY_KEY_PATH", verification_key_override.string().c_str());
#else
        setenv("PQ_ABSE_VERIFY_KEY_PATH", verification_key_override.string().c_str(), 1);
#endif
    } else {
#ifdef _WIN32
        _putenv_s("PQ_ABSE_VERIFY_KEY_PATH", "");
#else
        unsetenv("PQ_ABSE_VERIFY_KEY_PATH");
#endif
    }

    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
        return 1;
    }

    IdentityAuthority ia;
    Blockchain.sync_from_chain();
    SearchGateway gateway(ia);
    CloudRekeyState rekey_state;
    LoadCloudRekeyState(rekey_state);

    AuthToken token;
    if (!LoadAuthToken(request_dir / "auth_token.txt", token)) {
        std::cerr << "Failed to load auth token" << std::endl;
        return 2;
    }
    if (!skip_auth_verification && !gateway.VerifyAuthToken(token)) {
        std::cerr << "Authentication token verification failed" << std::endl;
        return 3;
    }

    SearchTrapdoor shortlist_trapdoor;
    if (!LoadSearchTrapdoor(params, shortlist_trapdoor, (request_dir / "shortlist_trapdoor.bin").string())) {
        std::cerr << "Failed to load shortlist trapdoor" << std::endl;
        return 4;
    }

    UserRecord user_record{token.user_gid, token.zk_id, "", token.leaf_index, false};

    const auto preferred_label = cli.Get("--preferred-label").empty()
        ? [&]() {
              std::string value;
              ReadTextFile(request_dir / "preferred_label.txt", value);
              return value;
          }()
        : cli.Get("--preferred-label");
    std::string preferred_label_token;
    ReadTextFile(request_dir / "preferred_label_token.txt", preferred_label_token);
    const std::size_t min_match_count = static_cast<std::size_t>(
        std::stoul(cli.Get("--min-match", std::to_string(DefaultMinMatchCount(shortlist_trapdoor)))));

    if (!rekey_state.update_token_seed.empty() &&
        rekey_state.epoch == Blockchain.current_state.epoch) {
        TrustedAuthority ta;
        std::string expected_token;
        if (!ta.generate_update_token_for_user(user_record, Blockchain.current_state.epoch, rekey_state.update_token_seed, expected_token)) {
            std::cerr << "Failed to derive expected update token" << std::endl;
            return 5;
        }
        if (token.update_token.empty() || token.update_token != expected_token) {
            std::cerr << "Missing or invalid update token for user " << token.user_gid << std::endl;
            return 5;
        }
    }

    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(Blockchain.current_state.epoch, epoch_bitmap_key)) {
        std::cerr << "Failed to derive epoch bitmap key" << std::endl;
        return 6;
    }

    const auto search_index = LoadOrBuildSearchIndex(params, Blockchain.current_state.epoch);
    const auto candidate_start = Clock::now();
    auto candidate_labels = search_index.ResolveLabels(
        search_index.CollectCandidatesAny(
            BuildEpochBitmapKeys(shortlist_trapdoor.keyword_tokens, Blockchain.current_state.epoch, epoch_bitmap_key)));
    const double candidate_generation_ms = ElapsedMilliseconds(candidate_start, Clock::now());

    if (!preferred_label_token.empty()) {
        std::vector<std::string> filtered_labels;
        filtered_labels.reserve(candidate_labels.size());
        for (const auto& label : candidate_labels) {
            StoredBundleRecord record;
            if (!LoadStoredBundleRecord(label, record)) {
                continue;
            }
            if (record.bundle_label_token == preferred_label_token) {
                filtered_labels.push_back(label);
            }
        }
        candidate_labels = std::move(filtered_labels);
    } else if (!preferred_label.empty()) {
        candidate_labels.erase(
            std::remove_if(candidate_labels.begin(), candidate_labels.end(),
                           [&](const std::string& label) { return label != preferred_label; }),
            candidate_labels.end());
    }

    std::filesystem::create_directories(response_dir / "bundles");
    const std::size_t candidate_count = candidate_labels.size();
    std::vector<RankedBundleMatch> ranked_matches;
    ranked_matches.reserve(candidate_labels.size());
    for (const auto& label : candidate_labels) {
        StoredBundleRecord record;
        if (!LoadStoredBundleRecord(label, record)) {
            continue;
        }
        CiphertextBundle bundle;
        if (!LoadCiphertextBundle(params, bundle, record.bundle_path)) {
            continue;
        }

        const bool epochStale = record.version_tag.epoch != Blockchain.current_state.epoch;
        if (NeedsLazyReencryption(record, bundle, rekey_state, Blockchain.current_state.epoch)) {
            if (rekey_state.re_encryption_key.empty() || rekey_state.epoch != Blockchain.current_state.epoch) {
                std::cerr << "Bundle " << label << " needs re-encryption but no valid rekey material is available" << std::endl;
                continue;
            }
            if (epochStale) {
                bundle.file_nonce = DeriveReencryptedFileNonce(bundle.file_nonce,
                                                               rekey_state,
                                                               record.bundle_label,
                                                               Blockchain.current_state.epoch);
            }
            ReEncryptCiphertextBundle(params,
                                      bundle,
                                      "epoch-" + std::to_string(Blockchain.current_state.epoch),
                                      rekey_state.re_encryption_key,
                                      rekey_state.update_token_seed);
            if (epochStale) {
                bundle.secure_index = BuildSecureIndex(params, bundle.keyword_set, bundle.file_nonce);
            }
            record.version_tag = Blockchain.current_state;
            record.is_reencrypted = true;
            SaveCiphertextBundle(params, bundle, record.bundle_path);
            SaveStoredBundleRecord(record);
        }

        std::vector<std::string> matched_keywords;
        const std::size_t matched_count = CountKeywordMatches(bundle, shortlist_trapdoor, matched_keywords);
        if (matched_count < min_match_count) {
            continue;
        }
        if (!PolicySatisfied(token.attributes, bundle.logical_policy)) {
            continue;
        }
        ranked_matches.push_back({label, matched_count, std::move(record)});
    }

    std::sort(ranked_matches.begin(), ranked_matches.end(), [](const RankedBundleMatch& lhs, const RankedBundleMatch& rhs) {
        if (lhs.matched_count != rhs.matched_count) {
            return lhs.matched_count > rhs.matched_count;
        }
        return lhs.label < rhs.label;
    });

    const std::size_t returned_count = std::min(max_results, ranked_matches.size());
    std::ostringstream ordered_bundle_manifest;
    for (std::size_t index = 0; index < returned_count; ++index) {
        const auto& match = ranked_matches[index];
        const auto response_bundle_path = response_dir / "bundles" / (match.label + "_bundle.bin");
        const auto response_meta_path = response_dir / "bundles" / (match.label + "_bundle.meta");
        std::filesystem::copy_file(match.record.bundle_path, response_bundle_path, std::filesystem::copy_options::overwrite_existing);
        std::filesystem::copy_file(BundleMetaPath(match.label), response_meta_path, std::filesystem::copy_options::overwrite_existing);
        ordered_bundle_manifest << match.label << "\t" << match.matched_count << "\n";
    }

    WriteTextFile(response_dir / "candidate_count.txt", std::to_string(candidate_count));
    WriteTextFile(response_dir / "exact_match_count.txt", std::to_string(returned_count));
    WriteTextFile(response_dir / "epoch.txt", std::to_string(Blockchain.current_state.epoch));
    WriteTextFile(response_dir / "bundle_order.txt", ordered_bundle_manifest.str());
    if (!candidate_timing_out.empty()) {
        std::ostringstream output;
        output << std::fixed << std::setprecision(3) << candidate_generation_ms;
        if (!WriteTextFile(candidate_timing_out, output.str())) {
            std::cerr << "Failed to write candidate generation timing" << std::endl;
            return 6;
        }
    }

    std::cout << "CS response prepared at " << response_dir << std::endl;
    std::cout << "Candidates: " << candidate_count
              << ", qualifying matches: " << ranked_matches.size()
              << ", returned: " << returned_count
              << ", min-match: " << min_match_count
              << ", max-results: " << max_results << std::endl;
    std::cout << "Candidate generation ms: " << std::fixed << std::setprecision(3) << candidate_generation_ms << std::endl;
    return 0;
}
