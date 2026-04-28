#include <algorithm>
#include <filesystem>
#include <iostream>
#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

#include "entities/SoftwareTee.h"
#include "phase1_setup.h"
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

using namespace abse_zkp;

std::size_t CountPolicyLeaves(const LogicalPolicy& policy) {
    if (policy.kind == PolicyKind::Attribute) {
        return 1;
    }
    std::size_t count = 0;
    for (const auto& child : policy.children) {
        count += CountPolicyLeaves(child);
    }
    return count;
}

template <typename T>
double AverageOrZero(const std::vector<T>& values) {
    if (values.empty()) {
        return 0.0;
    }
    const double sum = std::accumulate(values.begin(), values.end(), 0.0);
    return sum / static_cast<double>(values.size());
}

struct AggregateBucket {
    int size = 0;
    int runs = 0;
    std::vector<double> metric_a;
    std::vector<double> metric_b;
    std::vector<double> metric_c;
    std::vector<double> metric_d;
    std::vector<double> bytes;
};

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const auto scenario_path = std::filesystem::path(cli.Get("--scenario", DefaultScenarioPath().string()));
    const auto metrics_path =
        cli.Get("--metrics-out", (ExperimentArtifactRoot() / "encryption_benchmark_sweep.csv").string());
    const auto user_aggregate_path =
        cli.Get("--user-aggregate-out", (ExperimentArtifactRoot() / "encryption_user_aggregate.csv").string());
    const auto bundle_aggregate_path =
        cli.Get("--bundle-aggregate-out", (ExperimentArtifactRoot() / "encryption_bundle_aggregate.csv").string());
    const bool init_phase1_if_missing = cli.HasFlag("--init-phase1-if-missing");
    const bool rebuild_index = cli.HasFlag("--rebuild-index");

    const std::vector<std::string> metrics_header = {
        "phase", "kind", "name", "gid", "bundle_label", "epoch", "user_attr_count", "policy_attr_count",
        "keyword_count", "keygen_ms", "encrypt_bundle_ms", "mobile_encrypt_ms", "bundle_write_ms", "artifact_bytes"
    };
    const std::vector<std::string> user_aggregate_header = {
        "phase", "group_by", "attribute_count", "runs", "avg_keygen_ms", "avg_user_key_bytes"
    };
    const std::vector<std::string> bundle_aggregate_header = {
        "phase", "group_by", "policy_attribute_count", "runs", "avg_keyword_count", "avg_encrypt_bundle_ms",
        "avg_mobile_encrypt_ms", "avg_bundle_write_ms", "avg_bundle_bytes"
    };

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

    std::map<int, AggregateBucket> user_aggregates;
    std::map<int, AggregateBucket> bundle_aggregates;

    int auto_identity_secret = 1000;
    for (const auto& [name, user_input] : scenario.users) {
        const int identity_secret = user_input.has_identity_secret ? user_input.identity_secret : auto_identity_secret++;

        UserRecord user_record;
        if (!ia.get_user_record(user_input.gid, user_record)) {
            ia.register_user(user_input.gid, identity_secret);
        }

        UserSecretKey user_key;
        const auto keygen_start = Clock::now();
        tee.GenerateUserKey(params, pk, msk, user_input.gid, user_input.attributes, user_key, Blockchain.current_state.epoch, "");
        const double keygen_ms = ElapsedMilliseconds(keygen_start, Clock::now());
        const auto key_path = UserSecretKeyPath(user_input.gid);
        if (!SaveUserSecretKey(params, user_key, key_path.string())) {
            std::cerr << "Failed to save user key for " << user_input.gid << std::endl;
            return 3;
        }

        UserCredentialRecord record;
        record.gid = user_input.gid;
        record.identity_secret = identity_secret;
        record.local_epoch = Blockchain.current_state.epoch;
        record.user_key_path = key_path.string();
        record.attributes = user_input.attributes;
        if (!SaveUserCredentialRecord(record)) {
            std::cerr << "Failed to save credential for " << user_input.gid << std::endl;
            return 4;
        }

        AppendExperimentRow(metrics_path,
                            metrics_header,
                            {
                                ToCsvField("encryption_benchmark_sweep"),
                                ToCsvField("user"),
                                ToCsvField(name),
                                ToCsvField(user_input.gid),
                                ToCsvField(""),
                                ToCsvField(Blockchain.current_state.epoch),
                                ToCsvField(static_cast<uintmax_t>(user_input.attributes.size())),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(keygen_ms),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(FileSizeOrZero(key_path))
                            });

        auto& bucket = user_aggregates[static_cast<int>(user_input.attributes.size())];
        bucket.size = static_cast<int>(user_input.attributes.size());
        ++bucket.runs;
        bucket.metric_a.push_back(keygen_ms);
        bucket.bytes.push_back(static_cast<double>(FileSizeOrZero(key_path)));
    }

    for (const auto& [name, bundle_input] : scenario.bundles) {
        UserRecord owner_record;
        if (!ia.get_user_record(bundle_input.data_owner_gid, owner_record)) {
            std::cerr << "Unknown data owner gid in scenario: " << bundle_input.data_owner_gid << std::endl;
            return 5;
        }

        CiphertextBundle bundle;
        const auto encrypt_start = Clock::now();
        double mobile_encrypt_ms = 0.0;
        tee.CreateCiphertextBundle(params,
                                   pk,
                                   bundle_input.label,
                                   bundle_input.plaintext,
                                   bundle_input.keywords,
                                   bundle_input.policy,
                                   "epoch-" + std::to_string(Blockchain.current_state.epoch),
                                   bundle,
                                   &mobile_encrypt_ms);
        const double encrypt_bundle_ms = ElapsedMilliseconds(encrypt_start, Clock::now());

        const auto bundle_path = BundleBinaryPath(bundle_input.label);
        const auto write_start = Clock::now();
        if (!SaveCiphertextBundle(params, bundle, bundle_path.string())) {
            std::cerr << "Failed to save ciphertext bundle for " << bundle_input.label << std::endl;
            return 6;
        }
        StoredBundleRecord stored_record;
        stored_record.bundle_label = bundle_input.label;
        stored_record.bundle_path = bundle_path.string();
        stored_record.data_owner_gid = bundle_input.data_owner_gid;
        stored_record.version_tag = Blockchain.current_state;
        if (!SaveStoredBundleRecord(stored_record)) {
            std::cerr << "Failed to save bundle metadata for " << bundle_input.label << std::endl;
            return 7;
        }
        const double bundle_write_ms = ElapsedMilliseconds(write_start, Clock::now());
        const auto policy_leaf_count = CountPolicyLeaves(bundle_input.policy);

        AppendExperimentRow(metrics_path,
                            metrics_header,
                            {
                                ToCsvField("encryption_benchmark_sweep"),
                                ToCsvField("bundle"),
                                ToCsvField(name),
                                ToCsvField(bundle_input.data_owner_gid),
                                ToCsvField(bundle_input.label),
                                ToCsvField(Blockchain.current_state.epoch),
                                ToCsvField(""),
                                ToCsvField(static_cast<uintmax_t>(policy_leaf_count)),
                                ToCsvField(static_cast<uintmax_t>(bundle_input.keywords.size())),
                                ToCsvField(""),
                                ToCsvField(encrypt_bundle_ms),
                                ToCsvField(mobile_encrypt_ms),
                                ToCsvField(bundle_write_ms),
                                ToCsvField(FileSizeOrZero(bundle_path))
                            });

        auto& bucket = bundle_aggregates[static_cast<int>(policy_leaf_count)];
        bucket.size = static_cast<int>(policy_leaf_count);
        ++bucket.runs;
        bucket.metric_a.push_back(static_cast<double>(bundle_input.keywords.size()));
        bucket.metric_b.push_back(encrypt_bundle_ms);
        bucket.metric_c.push_back(mobile_encrypt_ms);
        bucket.metric_d.push_back(bundle_write_ms);
        bucket.bytes.push_back(static_cast<double>(FileSizeOrZero(bundle_path)));
    }

    if (rebuild_index) {
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
    }

    for (const auto& [size, bucket] : user_aggregates) {
        AppendExperimentRow(user_aggregate_path,
                            user_aggregate_header,
                            {
                                ToCsvField("encryption_benchmark_user_aggregate"),
                                ToCsvField("user_attributes"),
                                ToCsvField(size),
                                ToCsvField(bucket.runs),
                                ToCsvField(AverageOrZero(bucket.metric_a)),
                                ToCsvField(AverageOrZero(bucket.bytes))
                            });
    }

    for (const auto& [size, bucket] : bundle_aggregates) {
        AppendExperimentRow(bundle_aggregate_path,
                            bundle_aggregate_header,
                            {
                                ToCsvField("encryption_benchmark_bundle_aggregate"),
                                ToCsvField("policy_attributes"),
                                ToCsvField(size),
                                ToCsvField(bucket.runs),
                                ToCsvField(AverageOrZero(bucket.metric_a)),
                                ToCsvField(AverageOrZero(bucket.metric_b)),
                                ToCsvField(AverageOrZero(bucket.metric_c)),
                                ToCsvField(AverageOrZero(bucket.metric_d)),
                                ToCsvField(AverageOrZero(bucket.bytes))
                            });
    }

    std::cout << "Encryption benchmark sweep complete." << '\n';
    std::cout << "Users processed: " << scenario.users.size()
              << ", bundles processed: " << scenario.bundles.size() << '\n';
    return 0;
}
