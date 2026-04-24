#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "phase2_keygen.h"
#include "phase3_encrypt.h"

namespace abse_zkp {

struct SearchBenchmarkOptions {
    std::vector<std::string> query_keywords;
    std::string preferred_label;
    bool rebuild_index = false;
    bool respect_policy = false;
    bool decrypt_matches = false;
};

struct SearchBenchmarkSetMetrics {
    std::size_t matched_count = 0;
    double precision = 0.0;
    double recall = 0.0;
    double f1 = 0.0;
};

struct SearchBenchmarkResult {
    int epoch = 0;
    std::size_t corpus_size = 0;
    std::size_t query_keyword_count = 0;
    std::size_t ground_truth_count = 0;
    std::size_t candidate_count = 0;
    std::size_t exact_match_count = 0;
    std::size_t decrypt_success_count = 0;
    bool index_reused = false;
    double index_prepare_ms = 0.0;
    double trapdoor_gen_ms = 0.0;
    double candidate_prune_ms = 0.0;
    double exact_match_ms = 0.0;
    double retrieve_decrypt_ms = 0.0;
    double phase_total_ms = 0.0;
    uintmax_t benchmark_index_bytes = 0;
    SearchBenchmarkSetMetrics candidate_metrics;
    SearchBenchmarkSetMetrics exact_metrics;
    std::vector<std::string> ground_truth_labels;
    std::vector<std::string> candidate_labels;
    std::vector<std::string> exact_match_labels;
};

std::filesystem::path DefaultSearchBenchmarkMetricsPath();
SearchBenchmarkResult RunSearchBenchmark(const SystemParams& params,
                                         const UserSecretKey& user_key,
                                         const SearchBenchmarkOptions& options);

}  // namespace abse_zkp
