#include <filesystem>
#include <iostream>
#include <string>

#include "entities/SoftwareTee.h"
#include "phase1_setup.h"
#include "pq_src/Blockchain.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "search_include/Search.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const auto scenario_path = std::filesystem::path(cli.Get("--scenario", DefaultScenarioPath().string()));
    const bool init_phase1_if_missing = cli.HasFlag("--init-phase1-if-missing");
    const bool rebuild_all_user_keys = cli.HasFlag("--rebuild-user-keys");

    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        if (!init_phase1_if_missing) {
            std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
            return 1;
        }

        InitSystemParams(params, 256, 12289, 3.2, 2, false);
        Setup(params, pk, msk);
        if (!SavePhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
            std::cerr << "Failed to initialize Phase 1 artifacts" << std::endl;
            return 2;
        }
    }

    const auto scenario = LoadTestScenario(scenario_path);
    IdentityAuthority ia;
    Blockchain.sync_from_chain();
    SoftwareTee tee;

    int auto_identity_secret = 1000;
    for (const auto& [name, user_input] : scenario.users) {
        UserRecord user_record;
        const bool already_registered = ia.get_user_record(user_input.gid, user_record);
        const int identity_secret = user_input.has_identity_secret ? user_input.identity_secret : auto_identity_secret++;
        if (!already_registered) {
            ia.register_user(user_input.gid, identity_secret);
        }

        if (!already_registered || rebuild_all_user_keys || !std::filesystem::exists(UserSecretKeyPath(user_input.gid))) {
            UserSecretKey user_key;
            tee.GenerateUserKey(params, pk, msk, user_input.gid, user_input.attributes, user_key, Blockchain.current_state.epoch, "");
            if (!SaveUserSecretKey(params, user_key, UserSecretKeyPath(user_input.gid).string())) {
                std::cerr << "Failed to save user key for " << user_input.gid << std::endl;
                return 3;
            }

            UserCredentialRecord record;
            record.gid = user_input.gid;
            record.identity_secret = identity_secret;
            record.local_epoch = Blockchain.current_state.epoch;
            record.user_key_path = UserSecretKeyPath(user_input.gid).string();
            record.attributes = user_input.attributes;
            if (!SaveUserCredentialRecord(record)) {
                std::cerr << "Failed to save credential for " << user_input.gid << std::endl;
                return 4;
            }
        }
    }

    int bundle_count = 0;
    for (const auto& [name, bundle_input] : scenario.bundles) {
        UserRecord owner_record;
        if (!ia.get_user_record(bundle_input.data_owner_gid, owner_record)) {
            std::cerr << "Unknown data owner gid in scenario: " << bundle_input.data_owner_gid << std::endl;
            return 5;
        }

        CiphertextBundle bundle;
        tee.CreateCiphertextBundle(params,
                                   pk,
                                   bundle_input.label,
                                   bundle_input.plaintext,
                                   bundle_input.keywords,
                                   bundle_input.policy,
                                   "epoch-" + std::to_string(Blockchain.current_state.epoch),
                                   bundle);
        const auto bundle_path = BundleBinaryPath(bundle_input.label);
        if (!SaveCiphertextBundle(params, bundle, bundle_path.string())) {
            std::cerr << "Failed to save ciphertext bundle " << bundle_input.label << std::endl;
            return 6;
        }

        StoredBundleRecord record;
        record.bundle_label = bundle_input.label;
        record.bundle_path = bundle_path.string();
        record.data_owner_gid = bundle_input.data_owner_gid;
        record.version_tag = Blockchain.current_state;
        if (!SaveStoredBundleRecord(record)) {
            std::cerr << "Failed to save bundle metadata for " << bundle_input.label << std::endl;
            return 7;
        }
        ++bundle_count;
    }

    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(Blockchain.current_state.epoch, epoch_bitmap_key)) {
        std::cerr << "Failed to derive epoch bitmap key" << std::endl;
        return 8;
    }

    SearchOptimizationLayer rebuilt_index;
    for (const auto& indexed_label : ListStoredBundleLabels()) {
        StoredBundleRecord indexed_record;
        if (!LoadStoredBundleRecord(indexed_label, indexed_record)) {
            continue;
        }
        CiphertextBundle indexed_bundle;
        if (!LoadCiphertextBundle(params, indexed_bundle, indexed_record.bundle_path)) {
            continue;
        }
        rebuilt_index.ProcessNewUpload(indexed_label,
                                       indexed_bundle.secure_index,
                                       Blockchain.current_state.epoch,
                                       epoch_bitmap_key);
    }
    rebuilt_index.OptimizeAllBitmaps();
    const auto index_path = SearchArtifactRoot() / ("bitmap_index_epoch_" + std::to_string(Blockchain.current_state.epoch) + ".bin");
    if (!rebuilt_index.SaveToFile(index_path)) {
        std::cerr << "Failed to save rebuilt bitmap index" << std::endl;
        return 9;
    }

    std::cout << "Scenario materialized from " << scenario_path << '\n';
    std::cout << "Users processed: " << scenario.users.size() << '\n';
    std::cout << "Bundles materialized: " << bundle_count << '\n';
    std::cout << "Bitmap index rebuilt at: " << index_path << std::endl;
    return 0;
}
