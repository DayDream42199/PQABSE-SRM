#include "system/SearchBenchmark.h"

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <utility>

#include "phase4_search.h"
#include "pq_src/Blockchain.h"
#include "pq_src/TrustedAuthority.h"
#include "search_include/Search.h"
#include "system/Artifacts.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"

namespace abse_zkp {
namespace {

struct BenchmarkBundle {
    StoredBundleRecord record;
    CiphertextBundle bundle;
};

std::vector<std::string> CanonicalizeStrings(const std::vector<std::string>& values) {
    std::vector<std::string> canonical = values;
    std::sort(canonical.begin(), canonical.end());
    canonical.erase(std::unique(canonical.begin(), canonical.end()), canonical.end());
    return canonical;
}

std::filesystem::path BenchmarkIndexPath(int epoch) {
    return SearchArtifactRoot() / ("benchmark_bitmap_index_epoch_" + std::to_string(epoch) + ".bin");
}

std::vector<BenchmarkBundle> LoadBenchmarkBundles(const SystemParams& params) {
    std::vector<BenchmarkBundle> bundles;
    for (const auto& label : ListStoredBundleLabels()) {
        StoredBundleRecord record;
        if (!LoadStoredBundleRecord(label, record)) {
            continue;
        }

        CiphertextBundle bundle;
        if (!LoadCiphertextBundle(params, bundle, record.bundle_path)) {
            continue;
        }

        bundles.push_back({std::move(record), std::move(bundle)});
    }

    std::sort(bundles.begin(), bundles.end(), [](const BenchmarkBundle& lhs, const BenchmarkBundle& rhs) {
        return lhs.record.bundle_label < rhs.record.bundle_label;
    });
    return bundles;
}

SearchOptimizationLayer LoadOrBuildBenchmarkIndex(const std::vector<BenchmarkBundle>& bundles,
                                                  int epoch,
                                                  const std::string& epoch_bitmap_key,
                                                  bool rebuild_index,
                                                  bool& reused_index) {
    reused_index = false;
    const auto index_path = BenchmarkIndexPath(epoch);

    std::vector<std::string> labels;
    labels.reserve(bundles.size());
    for (const auto& entry : bundles) {
        labels.push_back(entry.record.bundle_label);
    }

    if (!rebuild_index) {
        SearchOptimizationLayer loaded;
        if (SearchOptimizationLayer::LoadFromFile(index_path, loaded) && loaded.KnownLabels() == labels) {
            reused_index = true;
            return loaded;
        }
    }

    SearchOptimizationLayer rebuilt;
    for (const auto& entry : bundles) {
        rebuilt.ProcessNewUpload(entry.record.bundle_label,
                                 entry.bundle.secure_index,
                                 epoch,
                                 epoch_bitmap_key);
    }
    rebuilt.OptimizeAllBitmaps();
    rebuilt.SaveToFile(index_path);
    return rebuilt;
}

SearchBenchmarkSetMetrics ComputeSetMetrics(const std::vector<std::string>& predicted,
                                            const std::vector<std::string>& ground_truth) {
    const std::set<std::string> predicted_set(predicted.begin(), predicted.end());
    const std::set<std::string> ground_truth_set(ground_truth.begin(), ground_truth.end());

    std::size_t matched = 0;
    for (const auto& label : predicted_set) {
        if (ground_truth_set.find(label) != ground_truth_set.end()) {
            ++matched;
        }
    }

    SearchBenchmarkSetMetrics metrics;
    metrics.matched_count = matched;
    if (!predicted_set.empty()) {
        metrics.precision = static_cast<double>(matched) / static_cast<double>(predicted_set.size());
    }
    if (!ground_truth_set.empty()) {
        metrics.recall = static_cast<double>(matched) / static_cast<double>(ground_truth_set.size());
    }
    if (metrics.precision > 0.0 || metrics.recall > 0.0) {
        metrics.f1 = (2.0 * metrics.precision * metrics.recall) / (metrics.precision + metrics.recall);
    }
    return metrics;
}

}  // namespace

std::filesystem::path DefaultSearchBenchmarkMetricsPath() {
    return ExperimentArtifactRoot() / "search_benchmark.csv";
}

SearchBenchmarkResult RunSearchBenchmark(const SystemParams& params,
                                         const UserSecretKey& user_key,
                                         const SearchBenchmarkOptions& options) {
    EnsureRuntimeDirectories();
    Blockchain.sync_from_chain();

    if (options.query_keywords.empty()) {
        throw std::runtime_error("Search benchmark requires at least one query keyword");
    }

    SearchBenchmarkResult result;
    result.epoch = Blockchain.current_state.epoch;
    const auto phase_start = Clock::now();

    const auto bundles = LoadBenchmarkBundles(params);
    result.corpus_size = bundles.size();
    const auto canonical_query_keywords = CanonicalizeStrings(options.query_keywords);
    result.query_keyword_count = canonical_query_keywords.size();
    if (bundles.empty()) {
        result.phase_total_ms = ElapsedMilliseconds(phase_start, Clock::now());
        return result;
    }

    TrustedAuthority ta;
    std::string epoch_bitmap_key;
    if (!ta.derive_bitmap_epoch_key(result.epoch, epoch_bitmap_key)) {
        throw std::runtime_error("Failed to derive epoch bitmap key for benchmark");
    }

    const auto index_start = Clock::now();
    bool reused_index = false;
    const SearchOptimizationLayer search_index =
        LoadOrBuildBenchmarkIndex(bundles, result.epoch, epoch_bitmap_key, options.rebuild_index, reused_index);
    result.index_reused = reused_index;
    result.index_prepare_ms = ElapsedMilliseconds(index_start, Clock::now());
    result.benchmark_index_bytes = FileSizeOrZero(BenchmarkIndexPath(result.epoch));

    SearchTrapdoor shortlist_trapdoor;
    std::array<unsigned char, 16> global_nonce{};
    const auto trapdoor_start = Clock::now();
    TrapGen(params, user_key, global_nonce, user_key.gid + "__benchmark", canonical_query_keywords, shortlist_trapdoor);
    result.trapdoor_gen_ms = ElapsedMilliseconds(trapdoor_start, Clock::now());

    for (const auto& entry : bundles) {
        if (!options.preferred_label.empty() && entry.record.bundle_label != options.preferred_label) {
            continue;
        }

        SearchTrapdoor retrieve_trapdoor;
        TrapGen(params,
                user_key,
                entry.bundle.file_nonce,
                user_key.gid + "__" + entry.record.bundle_label + "__ground_truth",
                canonical_query_keywords,
                retrieve_trapdoor);

        std::vector<std::string> matched_keywords;
        if (!Match(entry.bundle, retrieve_trapdoor, matched_keywords)) {
            continue;
        }
        if (options.respect_policy &&
            !PolicySatisfied(user_key.attributes, entry.bundle.logical_policy)) {
            continue;
        }
        result.ground_truth_labels.push_back(entry.record.bundle_label);
    }

    const auto prune_start = Clock::now();
    result.candidate_labels = search_index.ResolveLabels(
        search_index.ExecuteAdaptiveSearch(
            BuildEpochBitmapKeys(shortlist_trapdoor.keyword_tokens, result.epoch, epoch_bitmap_key)));
    result.candidate_prune_ms = ElapsedMilliseconds(prune_start, Clock::now());

    if (!options.preferred_label.empty()) {
        result.candidate_labels.erase(
            std::remove_if(result.candidate_labels.begin(),
                           result.candidate_labels.end(),
                           [&](const std::string& label) { return label != options.preferred_label; }),
            result.candidate_labels.end());
    }

    const auto exact_start = Clock::now();
    for (const auto& label : result.candidate_labels) {
        const auto it = std::find_if(bundles.begin(), bundles.end(), [&](const BenchmarkBundle& entry) {
            return entry.record.bundle_label == label;
        });
        if (it == bundles.end()) {
            continue;
        }

        SearchTrapdoor retrieve_trapdoor;
        TrapGen(params,
                user_key,
                it->bundle.file_nonce,
                user_key.gid + "__" + it->record.bundle_label + "__benchmark",
                canonical_query_keywords,
                retrieve_trapdoor);

        std::vector<std::string> matched_keywords;
        if (!Match(it->bundle, retrieve_trapdoor, matched_keywords)) {
            continue;
        }
        if (options.respect_policy &&
            !PolicySatisfied(user_key.attributes, it->bundle.logical_policy)) {
            continue;
        }

        result.exact_match_labels.push_back(it->record.bundle_label);

        if (options.decrypt_matches) {
            SearchResult decrypt_result;
            const auto decrypt_start = Clock::now();
            if (RetrieveAndDecrypt(params, user_key, it->bundle, retrieve_trapdoor, decrypt_result)) {
                ++result.decrypt_success_count;
            }
            result.retrieve_decrypt_ms += ElapsedMilliseconds(decrypt_start, Clock::now());
        }
    }
    result.exact_match_ms = ElapsedMilliseconds(exact_start, Clock::now());

    result.ground_truth_labels = CanonicalizeStrings(result.ground_truth_labels);
    result.candidate_labels = CanonicalizeStrings(result.candidate_labels);
    result.exact_match_labels = CanonicalizeStrings(result.exact_match_labels);

    result.ground_truth_count = result.ground_truth_labels.size();
    result.candidate_count = result.candidate_labels.size();
    result.exact_match_count = result.exact_match_labels.size();
    result.candidate_metrics = ComputeSetMetrics(result.candidate_labels, result.ground_truth_labels);
    result.exact_metrics = ComputeSetMetrics(result.exact_match_labels, result.ground_truth_labels);
    result.phase_total_ms = ElapsedMilliseconds(phase_start, Clock::now());
    return result;
}

}  // namespace abse_zkp
