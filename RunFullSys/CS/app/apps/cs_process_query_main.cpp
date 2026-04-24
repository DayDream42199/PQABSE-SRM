#include <algorithm>
#include <iostream>

#include "entities/SearchGateway.h"
#include "phase1_setup.h"
#include "phase4_search.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "search_include/Search.h"
#include "system/Artifacts.h"
#include "system/AuthTokenIO.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"

namespace {

using namespace abse_zkp;

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

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const auto request_dir = std::filesystem::path(cli.Require("--request-dir"));
    const auto response_dir = std::filesystem::path(cli.Require("--response-dir"));

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
    if (!gateway.VerifyAuthToken(token)) {
        std::cerr << "Authentication token verification failed" << std::endl;
        return 3;
    }

    SearchTrapdoor shortlist_trapdoor;
    if (!LoadSearchTrapdoor(params, shortlist_trapdoor, (request_dir / "shortlist_trapdoor.bin").string())) {
        std::cerr << "Failed to load shortlist trapdoor" << std::endl;
        return 4;
    }

    const auto preferred_label = cli.Get("--preferred-label").empty()
        ? [&]() {
              std::string value;
              ReadTextFile(request_dir / "preferred_label.txt", value);
              return value;
          }()
        : cli.Get("--preferred-label");

    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(Blockchain.current_state.epoch, epoch_bitmap_key)) {
        std::cerr << "Failed to derive epoch bitmap key" << std::endl;
        return 5;
    }

    const auto search_index = LoadOrBuildSearchIndex(params, Blockchain.current_state.epoch);
    auto candidate_labels = search_index.ResolveLabels(
        search_index.ExecuteAdaptiveSearch(
            BuildEpochBitmapKeys(shortlist_trapdoor.keyword_tokens, Blockchain.current_state.epoch, epoch_bitmap_key)));

    if (!preferred_label.empty()) {
        candidate_labels.erase(
            std::remove_if(candidate_labels.begin(), candidate_labels.end(),
                           [&](const std::string& label) { return label != preferred_label; }),
            candidate_labels.end());
    }

    std::filesystem::create_directories(response_dir / "bundles");
    std::size_t exact_match_count = 0;
    for (const auto& label : candidate_labels) {
        StoredBundleRecord record;
        if (!LoadStoredBundleRecord(label, record)) {
            continue;
        }
        CiphertextBundle bundle;
        if (!LoadCiphertextBundle(params, bundle, record.bundle_path)) {
            continue;
        }

        if (record.version_tag.epoch != Blockchain.current_state.epoch &&
            !rekey_state.re_encryption_key.empty() &&
            rekey_state.epoch == Blockchain.current_state.epoch) {
            ReEncryptCiphertextBundle(params,
                                      bundle,
                                      "epoch-" + std::to_string(Blockchain.current_state.epoch),
                                      rekey_state.re_encryption_key,
                                      rekey_state.update_token_seed);
            record.version_tag = Blockchain.current_state;
            record.is_reencrypted = true;
            SaveCiphertextBundle(params, bundle, record.bundle_path);
            SaveStoredBundleRecord(record);
        }

        std::vector<std::string> matched_keywords;
        if (!Match(bundle, shortlist_trapdoor, matched_keywords)) {
            continue;
        }

        const auto response_bundle_path = response_dir / "bundles" / (label + "_bundle.bin");
        const auto response_meta_path = response_dir / "bundles" / (label + "_bundle.meta");
        std::filesystem::copy_file(record.bundle_path, response_bundle_path, std::filesystem::copy_options::overwrite_existing);
        std::filesystem::copy_file(BundleMetaPath(label), response_meta_path, std::filesystem::copy_options::overwrite_existing);
        ++exact_match_count;
    }

    WriteTextFile(response_dir / "candidate_count.txt", std::to_string(candidate_labels.size()));
    WriteTextFile(response_dir / "exact_match_count.txt", std::to_string(exact_match_count));
    WriteTextFile(response_dir / "epoch.txt", std::to_string(Blockchain.current_state.epoch));

    std::cout << "CS response prepared at " << response_dir << std::endl;
    std::cout << "Candidates: " << candidate_labels.size() << ", exact matches: " << exact_match_count << std::endl;
    return 0;
}
