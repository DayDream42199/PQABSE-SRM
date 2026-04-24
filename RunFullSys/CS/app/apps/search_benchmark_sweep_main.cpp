#include <algorithm>
#include <filesystem>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

#include "phase1_setup.h"
#include "phase2_keygen.h"
#include "pq_src/Blockchain.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"
#include "system/SearchBenchmark.h"
#include "system/TestScenario.h"
#include "entities/SoftwareTee.h"

namespace {

using namespace abse_zkp;

std::vector<int> ParseIntList(const std::string& value) {
    std::vector<int> values;
    if (value.empty()) {
        return values;
    }

    std::size_t start = 0;
    while (start < value.size()) {
        const auto comma = value.find(',', start);
        const auto token = value.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (!token.empty()) {
            values.push_back(std::stoi(token));
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return values;
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
    int query_size = 0;
    int runs = 0;
    std::vector<double> index_prepare_ms;
    std::vector<double> trapdoor_gen_ms;
    std::vector<double> candidate_prune_ms;
    std::vector<double> exact_match_ms;
    std::vector<double> retrieve_decrypt_ms;
    std::vector<double> phase_total_ms;
    std::vector<double> candidate_precision;
    std::vector<double> candidate_recall;
    std::vector<double> candidate_f1;
    std::vector<double> exact_precision;
    std::vector<double> exact_recall;
    std::vector<double> exact_f1;
    std::vector<double> candidate_count;
    std::vector<double> exact_match_count;
    std::vector<double> ground_truth_count;
};

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const auto scenario_path = std::filesystem::path(cli.Get("--scenario", DefaultScenarioPath().string()));
    const auto metrics_path = cli.Get("--metrics-out", (ExperimentArtifactRoot() / "search_benchmark_sweep.csv").string());
    const auto aggregate_path =
        cli.Get("--aggregate-out", (ExperimentArtifactRoot() / "search_benchmark_sweep_aggregate.csv").string());
    const auto selected_sizes = ParseIntList(cli.Get("--query-sizes", ""));
    const std::string gid_filter = cli.Get("--gid");
    const bool respect_policy = cli.HasFlag("--respect-policy");
    const bool decrypt_matches = cli.HasFlag("--decrypt");
    const bool rebuild_each = cli.HasFlag("--rebuild-index-each");
    const bool provision_users = cli.HasFlag("--provision-users");
    const int limit_per_size = std::stoi(cli.Get("--limit-per-size", "0"));

    const std::vector<std::string> metrics_header = {
        "phase", "query_name", "gid", "preferred_label", "epoch", "respect_policy", "decrypt_matches",
        "query_keyword_count", "corpus_size", "ground_truth_count", "candidate_count",
        "exact_match_count", "decrypt_success_count", "index_reused", "index_prepare_ms",
        "trapdoor_gen_ms", "candidate_prune_ms", "exact_match_ms", "retrieve_decrypt_ms",
        "phase_total_ms", "benchmark_index_bytes", "candidate_precision", "candidate_recall",
        "candidate_f1", "exact_precision", "exact_recall", "exact_f1"
    };
    const std::vector<std::string> aggregate_header = {
        "phase", "query_keyword_count", "runs", "respect_policy", "decrypt_matches",
        "avg_ground_truth_count", "avg_candidate_count", "avg_exact_match_count",
        "avg_index_prepare_ms", "avg_trapdoor_gen_ms", "avg_candidate_prune_ms",
        "avg_exact_match_ms", "avg_retrieve_decrypt_ms", "avg_phase_total_ms",
        "avg_candidate_precision", "avg_candidate_recall", "avg_candidate_f1",
        "avg_exact_precision", "avg_exact_recall", "avg_exact_f1"
    };

    const auto scenario = LoadTestScenario(scenario_path);

    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
        return 1;
    }
    Blockchain.sync_from_chain();

    std::map<int, int> runs_by_size;
    std::map<int, AggregateBucket> aggregates;
    SoftwareTee tee;

    for (const auto& [query_name, query] : scenario.queries) {
        const int query_size = static_cast<int>(query.keywords.size());
        if (!selected_sizes.empty() &&
            std::find(selected_sizes.begin(), selected_sizes.end(), query_size) == selected_sizes.end()) {
            continue;
        }
        if (!gid_filter.empty() && query.gid != gid_filter) {
            continue;
        }
        if (limit_per_size > 0 && runs_by_size[query_size] >= limit_per_size) {
            continue;
        }

        UserCredentialRecord credential;
        if (!LoadUserCredentialRecord(query.gid, credential)) {
            const auto scenario_user_it = scenario.users.find(query.gid);
            if (!provision_users || scenario_user_it == scenario.users.end()) {
                std::cerr << "Skipping query " << query_name << ": missing credential for " << query.gid << std::endl;
                continue;
            }

            UserSecretKey generated_user_key;
            tee.GenerateUserKey(params,
                                pk,
                                msk,
                                scenario_user_it->second.gid,
                                scenario_user_it->second.attributes,
                                generated_user_key,
                                Blockchain.current_state.epoch,
                                "");
            const auto user_key_path = UserSecretKeyPath(scenario_user_it->second.gid);
            if (!SaveUserSecretKey(params, generated_user_key, user_key_path.string())) {
                std::cerr << "Skipping query " << query_name << ": failed to save generated key for " << query.gid << std::endl;
                continue;
            }

            credential.gid = scenario_user_it->second.gid;
            credential.identity_secret = scenario_user_it->second.identity_secret;
            credential.local_epoch = Blockchain.current_state.epoch;
            credential.user_key_path = user_key_path.string();
            credential.attributes = scenario_user_it->second.attributes;
            if (!SaveUserCredentialRecord(credential)) {
                std::cerr << "Skipping query " << query_name << ": failed to save generated credential for " << query.gid << std::endl;
                continue;
            }
        }

        UserSecretKey user_key;
        if (!LoadUserSecretKey(params, user_key, credential.user_key_path)) {
            std::cerr << "Skipping query " << query_name << ": missing user key for " << query.gid << std::endl;
            continue;
        }

        SearchBenchmarkOptions options;
        options.query_keywords = query.keywords;
        options.preferred_label = query.bundle_label;
        options.rebuild_index = rebuild_each;
        options.respect_policy = respect_policy;
        options.decrypt_matches = decrypt_matches;

        const auto result = RunSearchBenchmark(params, user_key, options);
        AppendExperimentRow(metrics_path,
                            metrics_header,
                            {
                                ToCsvField("search_benchmark_sweep"),
                                ToCsvField(query_name),
                                ToCsvField(query.gid),
                                ToCsvField(query.bundle_label),
                                ToCsvField(result.epoch),
                                ToCsvField(respect_policy),
                                ToCsvField(decrypt_matches),
                                ToCsvField(static_cast<uintmax_t>(result.query_keyword_count)),
                                ToCsvField(static_cast<uintmax_t>(result.corpus_size)),
                                ToCsvField(static_cast<uintmax_t>(result.ground_truth_count)),
                                ToCsvField(static_cast<uintmax_t>(result.candidate_count)),
                                ToCsvField(static_cast<uintmax_t>(result.exact_match_count)),
                                ToCsvField(static_cast<uintmax_t>(result.decrypt_success_count)),
                                ToCsvField(result.index_reused),
                                ToCsvField(result.index_prepare_ms),
                                ToCsvField(result.trapdoor_gen_ms),
                                ToCsvField(result.candidate_prune_ms),
                                ToCsvField(result.exact_match_ms),
                                ToCsvField(result.retrieve_decrypt_ms),
                                ToCsvField(result.phase_total_ms),
                                ToCsvField(result.benchmark_index_bytes),
                                ToCsvField(result.candidate_metrics.precision),
                                ToCsvField(result.candidate_metrics.recall),
                                ToCsvField(result.candidate_metrics.f1),
                                ToCsvField(result.exact_metrics.precision),
                                ToCsvField(result.exact_metrics.recall),
                                ToCsvField(result.exact_metrics.f1)
                            });

        auto& bucket = aggregates[query_size];
        bucket.query_size = query_size;
        ++bucket.runs;
        bucket.index_prepare_ms.push_back(result.index_prepare_ms);
        bucket.trapdoor_gen_ms.push_back(result.trapdoor_gen_ms);
        bucket.candidate_prune_ms.push_back(result.candidate_prune_ms);
        bucket.exact_match_ms.push_back(result.exact_match_ms);
        bucket.retrieve_decrypt_ms.push_back(result.retrieve_decrypt_ms);
        bucket.phase_total_ms.push_back(result.phase_total_ms);
        bucket.candidate_precision.push_back(result.candidate_metrics.precision);
        bucket.candidate_recall.push_back(result.candidate_metrics.recall);
        bucket.candidate_f1.push_back(result.candidate_metrics.f1);
        bucket.exact_precision.push_back(result.exact_metrics.precision);
        bucket.exact_recall.push_back(result.exact_metrics.recall);
        bucket.exact_f1.push_back(result.exact_metrics.f1);
        bucket.candidate_count.push_back(static_cast<double>(result.candidate_count));
        bucket.exact_match_count.push_back(static_cast<double>(result.exact_match_count));
        bucket.ground_truth_count.push_back(static_cast<double>(result.ground_truth_count));
        ++runs_by_size[query_size];
    }

    for (const auto& [query_size, bucket] : aggregates) {
        AppendExperimentRow(aggregate_path,
                            aggregate_header,
                            {
                                ToCsvField("search_benchmark_sweep_aggregate"),
                                ToCsvField(query_size),
                                ToCsvField(bucket.runs),
                                ToCsvField(respect_policy),
                                ToCsvField(decrypt_matches),
                                ToCsvField(AverageOrZero(bucket.ground_truth_count)),
                                ToCsvField(AverageOrZero(bucket.candidate_count)),
                                ToCsvField(AverageOrZero(bucket.exact_match_count)),
                                ToCsvField(AverageOrZero(bucket.index_prepare_ms)),
                                ToCsvField(AverageOrZero(bucket.trapdoor_gen_ms)),
                                ToCsvField(AverageOrZero(bucket.candidate_prune_ms)),
                                ToCsvField(AverageOrZero(bucket.exact_match_ms)),
                                ToCsvField(AverageOrZero(bucket.retrieve_decrypt_ms)),
                                ToCsvField(AverageOrZero(bucket.phase_total_ms)),
                                ToCsvField(AverageOrZero(bucket.candidate_precision)),
                                ToCsvField(AverageOrZero(bucket.candidate_recall)),
                                ToCsvField(AverageOrZero(bucket.candidate_f1)),
                                ToCsvField(AverageOrZero(bucket.exact_precision)),
                                ToCsvField(AverageOrZero(bucket.exact_recall)),
                                ToCsvField(AverageOrZero(bucket.exact_f1))
                            });
    }

    std::cout << "Search benchmark sweep complete for " << aggregates.size() << " query-size bucket(s)." << '\n';
    for (const auto& [query_size, bucket] : aggregates) {
        std::cout << "q=" << query_size
                  << " runs=" << bucket.runs
                  << " avg_total_ms=" << AverageOrZero(bucket.phase_total_ms)
                  << " avg_exact_f1=" << AverageOrZero(bucket.exact_f1) << '\n';
    }
    return 0;
}
