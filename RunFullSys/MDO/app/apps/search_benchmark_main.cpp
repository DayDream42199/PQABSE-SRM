#include <iostream>

#include "phase1_setup.h"
#include "phase2_keygen.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"
#include "system/SearchBenchmark.h"
#include "system/TestScenario.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    std::string gid;
    std::string preferred_label;
    std::vector<std::string> query_keywords;
    if (!cli.Get("--query").empty()) {
        const auto scenario = LoadTestScenario(cli.Get("--scenario", DefaultScenarioPath().string()));
        const auto& query = GetScenarioQuery(scenario, cli.Get("--query"));
        gid = query.gid;
        preferred_label = query.bundle_label;
        query_keywords = query.keywords;
    } else {
        gid = cli.Require("--gid");
        preferred_label = cli.Get("--label");
        query_keywords = cli.GetAll("--query-keyword");
        if (query_keywords.empty()) {
            throw std::runtime_error("Provide at least one --query-keyword or use --query");
        }
    }

    const auto metrics_path = cli.Get("--metrics-out", DefaultSearchBenchmarkMetricsPath().string());
    const std::vector<std::string> metrics_header = {
        "phase", "gid", "preferred_label", "epoch", "respect_policy", "decrypt_matches",
        "query_keyword_count", "corpus_size", "ground_truth_count", "candidate_count",
        "exact_match_count", "decrypt_success_count", "index_reused", "index_prepare_ms",
        "trapdoor_gen_ms", "candidate_prune_ms", "exact_match_ms", "retrieve_decrypt_ms",
        "phase_total_ms", "benchmark_index_bytes", "candidate_precision", "candidate_recall",
        "candidate_f1", "exact_precision", "exact_recall", "exact_f1"
    };

    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
        return 1;
    }

    UserCredentialRecord credential;
    if (!LoadUserCredentialRecord(gid, credential)) {
        std::cerr << "Failed to load credential for " << gid << std::endl;
        return 2;
    }

    UserSecretKey user_key;
    if (!LoadUserSecretKey(params, user_key, credential.user_key_path)) {
        std::cerr << "Failed to load user secret key for " << gid << std::endl;
        return 3;
    }

    SearchBenchmarkOptions options;
    options.query_keywords = query_keywords;
    options.preferred_label = preferred_label;
    options.rebuild_index = cli.HasFlag("--rebuild-index");
    options.respect_policy = cli.HasFlag("--respect-policy");
    options.decrypt_matches = cli.HasFlag("--decrypt");

    const auto result = RunSearchBenchmark(params, user_key, options);

    AppendExperimentRow(metrics_path,
                        metrics_header,
                        {
                            ToCsvField("search_benchmark"),
                            ToCsvField(gid),
                            ToCsvField(preferred_label),
                            ToCsvField(result.epoch),
                            ToCsvField(options.respect_policy),
                            ToCsvField(options.decrypt_matches),
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

    std::cout << "Benchmark complete for gid " << gid << '\n';
    std::cout << "Corpus bundles: " << result.corpus_size << '\n';
    std::cout << "Ground truth bundles: " << result.ground_truth_count << '\n';
    std::cout << "Candidate bundles: " << result.candidate_count << '\n';
    std::cout << "Exact match bundles: " << result.exact_match_count << '\n';
    if (options.decrypt_matches) {
        std::cout << "Decrypt successes: " << result.decrypt_success_count << '\n';
    }
    std::cout << "Timings (ms): index=" << result.index_prepare_ms
              << ", trapdoor=" << result.trapdoor_gen_ms
              << ", prune=" << result.candidate_prune_ms
              << ", exact=" << result.exact_match_ms
              << ", decrypt=" << result.retrieve_decrypt_ms
              << ", total=" << result.phase_total_ms << '\n';
    std::cout << "Exact precision/recall/f1: "
              << result.exact_metrics.precision << '/'
              << result.exact_metrics.recall << '/'
              << result.exact_metrics.f1 << '\n';
    return 0;
}
