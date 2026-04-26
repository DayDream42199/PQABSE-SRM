#include <iostream>

#include "entities/NitroTeeClient.h"
#include "entities/SoftwareTee.h"
#include "phase1_setup.h"
#include "phase3_encrypt.h"
#include "pq_src/Blockchain.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "search_include/Search.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

namespace {

abse_zkp::NitroTeeOptions LoadNitroOptions(const abse_zkp::CliArgs& cli) {
    abse_zkp::NitroTeeOptions options;
    options.enclave_cid = static_cast<std::uint32_t>(std::stoul(cli.Get("--nitro-cid", "16")));
    options.port = static_cast<std::uint32_t>(std::stoul(cli.Get("--nitro-port", "5005")));
    options.timeout_ms = std::stoi(cli.Get("--nitro-timeout-ms", "30000"));
    return options;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    std::string data_owner_gid;
    std::string label;
    std::string plaintext;
    std::vector<std::string> keywords;
    LogicalPolicy logical_policy;
    const auto metrics_path = cli.Get("--metrics-out", DefaultExperimentMetricsPath().string());
    const std::vector<std::string> metrics_header = {
        "phase", "gid", "owner_gid", "revoked_gid", "preferred_label", "matched_label", "bundle_label",
        "epoch", "keyword_count", "query_keyword_count", "candidate_count", "active_user_count",
        "cache_hit", "search_success", "encrypt_bundle_ms", "bundle_write_ms", "index_update_ms",
        "trapdoor_gen_ms", "auth_verify_ms", "index_prepare_ms", "candidate_prune_ms",
        "retrieve_decrypt_ms", "revoke_ms", "rekey_material_ms", "update_token_write_ms",
        "phase_total_ms", "bundle_bytes", "bundle_meta_bytes", "bitmap_index_bytes",
        "cloud_rekey_bytes", "update_token_bytes"
    };

    if (!cli.Get("--bundle").empty()) {
        const auto scenario = LoadTestScenario(cli.Get("--scenario", DefaultScenarioPath().string()));
        const auto& bundle_input = GetScenarioBundle(scenario, cli.Get("--bundle"));
        data_owner_gid = bundle_input.data_owner_gid;
        label = bundle_input.label;
        plaintext = bundle_input.plaintext;
        keywords = bundle_input.keywords;
        logical_policy = bundle_input.policy;
    } else {
        data_owner_gid = cli.Get("--data-owner-gid");
        if (data_owner_gid.empty()) {
            data_owner_gid = cli.Require("--owner-gid");
        }
        label = cli.Require("--label");
        plaintext = cli.Require("--plaintext");
        keywords = cli.GetAll("--keyword");
        if (keywords.empty()) keywords = {"default"};
        const std::string policy_expression = cli.Get("--policy-expression");
        if (!policy_expression.empty()) {
            logical_policy = BuildLogicalPolicyFromExpression(policy_expression);
        } else {
            const std::string policy_type = cli.Get("--policy-type", "and");
            auto policy_attrs = cli.GetAll("--policy-attr");
            if (policy_attrs.empty()) policy_attrs = {"default"};
            const std::size_t threshold = static_cast<std::size_t>(std::stoull(cli.Get("--threshold", "1")));
            logical_policy = BuildLogicalPolicyFromParts(policy_type, policy_attrs, threshold);
        }
    }

    IdentityAuthority ia;
    UserRecord owner_record;
    if (!ia.get_user_record(data_owner_gid, owner_record)) { std::cerr << "Unknown data owner gid: " << data_owner_gid << std::endl; return 1; }
    Blockchain.sync_from_chain();

    SystemParams params{}; PK pk; MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) { std::cerr << "Failed to load Phase 1 artifacts" << std::endl; return 2; }
    const bool use_nitro = cli.Get("--tee-mode", "software") == "nitro";
    const auto nitro_options = LoadNitroOptions(cli);
    SoftwareTee tee;
    NitroTeeClient nitro_tee;
    CiphertextBundle bundle;
    const auto phase_start = Clock::now();
    const auto encrypt_start = Clock::now();
    if (use_nitro) {
        nitro_tee.CreateCiphertextBundle(params,
                                         pk,
                                         msk,
                                         label,
                                         plaintext,
                                         keywords,
                                         logical_policy,
                                         "epoch-" + std::to_string(Blockchain.current_state.epoch),
                                         bundle,
                                         nitro_options);
    } else {
        tee.CreateCiphertextBundle(params, pk, label, plaintext, keywords, logical_policy, "epoch-" + std::to_string(Blockchain.current_state.epoch), bundle);
    }
    const double encrypt_bundle_ms = ElapsedMilliseconds(encrypt_start, Clock::now());
    const auto bundle_path = BundleBinaryPath(label);
    const auto write_start = Clock::now();
    if (!SaveCiphertextBundle(params, bundle, bundle_path.string())) { std::cerr << "Failed to save ciphertext bundle" << std::endl; return 3; }
    StoredBundleRecord record; record.bundle_label = label; record.bundle_path = bundle_path.string(); record.data_owner_gid = data_owner_gid; record.version_tag = Blockchain.current_state;
    if (!SaveStoredBundleRecord(record)) { std::cerr << "Failed to save bundle metadata" << std::endl; return 4; }
    const double bundle_write_ms = ElapsedMilliseconds(write_start, Clock::now());

    const auto index_path = SearchArtifactRoot() / ("bitmap_index_epoch_" + std::to_string(Blockchain.current_state.epoch) + ".bin");
    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(Blockchain.current_state.epoch, epoch_bitmap_key)) {
        std::cerr << "Failed to derive epoch bitmap key" << std::endl;
        return 5;
    }
    const auto index_update_start = Clock::now();
    SearchOptimizationLayer search_index;
    const bool loaded_index = SearchOptimizationLayer::LoadFromFile(index_path, search_index);
    if (loaded_index && !search_index.ContainsLabel(label)) {
        search_index.ProcessNewUpload(label, bundle.secure_index, Blockchain.current_state.epoch, epoch_bitmap_key);
        search_index.OptimizeAllBitmaps();
    } else {
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
        search_index = std::move(rebuilt_index);
    }

    if (!search_index.SaveToFile(index_path)) { std::cerr << "Failed to persist bitmap index" << std::endl; return 6; }
    const double index_update_ms = ElapsedMilliseconds(index_update_start, Clock::now());
    const double phase_total_ms = ElapsedMilliseconds(phase_start, Clock::now());
    AppendExperimentRow(metrics_path,
                        metrics_header,
                        {
                            ToCsvField("phase3_encrypt"),
                            ToCsvField(""),
                            ToCsvField(data_owner_gid),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(label),
                            ToCsvField(Blockchain.current_state.epoch),
                            ToCsvField(static_cast<uint64_t>(keywords.size())),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(encrypt_bundle_ms),
                            ToCsvField(bundle_write_ms),
                            ToCsvField(index_update_ms),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(phase_total_ms),
                            ToCsvField(FileSizeOrZero(bundle_path)),
                            ToCsvField(FileSizeOrZero(BundleMetaPath(label))),
                            ToCsvField(FileSizeOrZero(index_path)),
                            ToCsvField(""),
                            ToCsvField("")
                        });

    std::cout << "Phase 3 encryption complete for bundle " << label << std::endl;
    return 0;
}
