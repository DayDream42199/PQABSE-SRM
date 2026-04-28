#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "entities/SoftwareTee.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"

namespace {

using namespace abse_zkp;

struct SyntheticUser {
    std::string gid;
    int identity_secret = 0;
    std::vector<std::string> attributes;
};

struct SyntheticBundle {
    std::string label;
    std::string owner_gid;
    std::string plaintext;
    std::vector<std::string> keywords;
    std::vector<std::string> policy_attributes;
    std::string policy_expression;
    std::vector<std::string> authorized_gids;
};

struct KeywordBands {
    std::vector<std::string> common;
    std::vector<std::string> medium;
    std::vector<std::string> rare;
    std::vector<std::string> selective;
};

std::string PadNumber(std::size_t value, int width = 4) {
    std::ostringstream out;
    out << std::setw(width) << std::setfill('0') << value;
    return out.str();
}

std::vector<int> ParseIntList(const std::string& value) {
    std::vector<int> values;
    if (value.empty()) {
        return values;
    }

    std::stringstream input(value);
    std::string item;
    while (std::getline(input, item, ',')) {
        if (!item.empty()) {
            values.push_back(std::stoi(item));
        }
    }
    return values;
}

template <typename T>
std::string JoinStrings(const std::vector<T>& values, const std::string& delimiter = ",") {
    std::ostringstream out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            out << delimiter;
        }
        out << values[i];
    }
    return out.str();
}

template <typename T>
std::vector<T> SampleWithoutReplacement(const std::vector<T>& pool, std::size_t count, std::mt19937& rng) {
    if (count > pool.size()) {
        throw std::invalid_argument("sample size exceeds pool size");
    }

    std::vector<std::size_t> indices(pool.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::shuffle(indices.begin(), indices.end(), rng);

    std::vector<T> sampled;
    sampled.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        sampled.push_back(pool[indices[i]]);
    }
    std::sort(sampled.begin(), sampled.end());
    return sampled;
}

std::string MakePolicyExpression(const std::string& policy_type,
                                 const std::vector<std::string>& attributes,
                                 std::size_t threshold) {
    if (policy_type == "attribute") {
        if (attributes.size() != 1) {
            throw std::invalid_argument("attribute policy requires exactly one attribute");
        }
        return attributes.front();
    }
    if (policy_type == "and") {
        return "AND(" + JoinStrings(attributes) + ")";
    }
    if (policy_type == "or") {
        return "OR(" + JoinStrings(attributes) + ")";
    }
    if (policy_type == "threshold") {
        return "THRESHOLD(" + std::to_string(threshold) + "," + JoinStrings(attributes) + ")";
    }
    throw std::invalid_argument("unsupported policy type: " + policy_type);
}

std::vector<std::string> MakeKeywordPool(std::size_t count) {
    std::vector<std::string> pool;
    pool.reserve(count);
    for (std::size_t i = 1; i <= count; ++i) {
        pool.push_back("kw_" + PadNumber(i));
    }
    return pool;
}

KeywordBands SplitKeywordBands(const std::vector<std::string>& pool,
                               std::size_t common_count,
                               std::size_t medium_count,
                               std::size_t rare_count) {
    if (common_count + medium_count + rare_count > pool.size()) {
        throw std::invalid_argument("keyword band sizes exceed keyword pool");
    }

    KeywordBands bands;
    auto begin = pool.begin();
    bands.common.assign(begin, begin + static_cast<std::ptrdiff_t>(common_count));
    begin += static_cast<std::ptrdiff_t>(common_count);
    bands.medium.assign(begin, begin + static_cast<std::ptrdiff_t>(medium_count));
    begin += static_cast<std::ptrdiff_t>(medium_count);
    bands.rare.assign(begin, begin + static_cast<std::ptrdiff_t>(rare_count));
    begin += static_cast<std::ptrdiff_t>(rare_count);
    bands.selective.assign(begin, pool.end());
    return bands;
}

std::vector<std::string> MakeAttributePool(std::size_t count) {
    std::vector<std::string> pool;
    pool.reserve(count);
    for (std::size_t i = 1; i <= count; ++i) {
        pool.push_back("attr_" + PadNumber(i));
    }
    return pool;
}

std::size_t ClampQuota(int requested, std::size_t remaining, const char* label) {
    if (requested < 0) {
        throw std::invalid_argument(std::string(label) + " cannot be negative");
    }
    if (static_cast<std::size_t>(requested) > remaining) {
        throw std::invalid_argument(std::string(label) + " exceeds keywords-per-bundle");
    }
    return static_cast<std::size_t>(requested);
}

std::vector<std::string> BuildBundleKeywords(
    const KeywordBands& bands,
    std::size_t bundle_index,
    std::size_t bundle_count,
    std::size_t keywords_per_bundle,
    std::size_t common_per_bundle,
    std::size_t medium_per_bundle,
    std::size_t rare_per_bundle,
    std::size_t selective_per_bundle,
    std::size_t selective_cluster_span,
    std::mt19937& rng) {
    if (common_per_bundle > bands.common.size() ||
        medium_per_bundle > bands.medium.size() ||
        rare_per_bundle > bands.rare.size() ||
        selective_per_bundle > bands.selective.size()) {
        throw std::invalid_argument("per-bundle keyword quota exceeds corresponding band size");
    }

    std::vector<std::string> keywords;
    keywords.reserve(keywords_per_bundle);
    std::unordered_set<std::string> seen;

    auto append_unique = [&](const std::vector<std::string>& values) {
        for (const auto& value : values) {
            if (seen.insert(value).second) {
                keywords.push_back(value);
            }
        }
    };

    append_unique(SampleWithoutReplacement(bands.common, common_per_bundle, rng));
    append_unique(SampleWithoutReplacement(bands.medium, medium_per_bundle, rng));
    append_unique(SampleWithoutReplacement(bands.rare, rare_per_bundle, rng));

    if (!bands.selective.empty() && selective_per_bundle > 0) {
        const std::size_t span = std::max<std::size_t>(1, selective_cluster_span);
        const std::size_t cluster_count =
            std::max<std::size_t>(1, (bundle_count + span - 1) / span);
        const std::size_t cluster_id = bundle_index / span;
        const std::size_t selective_bucket_width =
            std::max<std::size_t>(selective_per_bundle, (bands.selective.size() + cluster_count - 1) / cluster_count);
        const std::size_t selective_begin = std::min(cluster_id * selective_bucket_width, bands.selective.size());
        const std::size_t selective_end = std::min(selective_begin + selective_bucket_width, bands.selective.size());
        std::vector<std::string> selective_bucket(
            bands.selective.begin() + static_cast<std::ptrdiff_t>(selective_begin),
            bands.selective.begin() + static_cast<std::ptrdiff_t>(selective_end));
        if (selective_bucket.size() < selective_per_bundle) {
            selective_bucket = bands.selective;
        }
        append_unique(SampleWithoutReplacement(selective_bucket, selective_per_bundle, rng));
    }

    std::vector<std::string> fallback_pool = bands.medium;
    fallback_pool.insert(fallback_pool.end(), bands.rare.begin(), bands.rare.end());
    fallback_pool.insert(fallback_pool.end(), bands.selective.begin(), bands.selective.end());
    if (fallback_pool.empty()) {
        fallback_pool = bands.common;
    }
    std::shuffle(fallback_pool.begin(), fallback_pool.end(), rng);
    for (const auto& keyword : fallback_pool) {
        if (keywords.size() >= keywords_per_bundle) {
            break;
        }
        if (seen.insert(keyword).second) {
            keywords.push_back(keyword);
        }
    }

    if (keywords.size() != keywords_per_bundle) {
        throw std::runtime_error("failed to build enough unique keywords for synthetic bundle");
    }

    std::sort(keywords.begin(), keywords.end());
    return keywords;
}

void WriteScenarioFile(const std::filesystem::path& output_path,
                       const std::vector<SyntheticUser>& users,
                       const std::vector<SyntheticBundle>& bundles,
                       const std::vector<int>& query_sizes,
                       int queries_per_size,
                       int revocation_count,
                       std::mt19937& rng) {
    std::filesystem::create_directories(output_path.parent_path());
    std::ofstream output(output_path, std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("failed to open synthetic scenario output: " + output_path.string());
    }

    output << "# Synthetic benchmark scenario generated by generate_synthetic_scenario.\n";
    output << "# Users=" << users.size()
           << ", bundles=" << bundles.size()
           << ", query_sizes=" << JoinStrings(query_sizes)
           << ", queries_per_size=" << queries_per_size << "\n\n";

    for (const auto& user : users) {
        output << "user." << user.gid << ".identity_secret=" << user.identity_secret << '\n';
        output << "user." << user.gid << ".attributes=" << JoinStrings(user.attributes) << "\n\n";
    }

    for (const auto& bundle : bundles) {
        output << "bundle." << bundle.label << ".data_owner_gid=" << bundle.owner_gid << '\n';
        output << "bundle." << bundle.label << ".plaintext=" << bundle.plaintext << '\n';
        output << "bundle." << bundle.label << ".keywords=" << JoinStrings(bundle.keywords) << '\n';
        output << "bundle." << bundle.label << ".policy=" << bundle.policy_expression << "\n\n";
    }

    for (int query_size : query_sizes) {
        std::vector<std::size_t> eligible_bundles;
        for (std::size_t i = 0; i < bundles.size(); ++i) {
            if (static_cast<std::size_t>(query_size) <= bundles[i].keywords.size() &&
                !bundles[i].authorized_gids.empty()) {
                eligible_bundles.push_back(i);
            }
        }
        if (eligible_bundles.empty()) {
            throw std::runtime_error("no eligible bundles available for query size " + std::to_string(query_size));
        }

        std::uniform_int_distribution<std::size_t> bundle_distribution(0, eligible_bundles.size() - 1);
        for (int q = 1; q <= queries_per_size; ++q) {
            const auto& bundle = bundles[eligible_bundles[bundle_distribution(rng)]];
            const auto query_keywords =
                SampleWithoutReplacement(bundle.keywords, static_cast<std::size_t>(query_size), rng);
            std::uniform_int_distribution<std::size_t> user_distribution(0, bundle.authorized_gids.size() - 1);
            const std::string query_name = "q" + std::to_string(query_size) + "_" + std::to_string(q);
            output << "query." << query_name << ".gid=" << bundle.authorized_gids[user_distribution(rng)] << '\n';
            output << "query." << query_name << ".bundle_label=" << bundle.label << '\n';
            output << "query." << query_name << ".keywords=" << JoinStrings(query_keywords) << "\n\n";
        }
    }

    for (int i = 0; i < revocation_count && i < static_cast<int>(users.size()); ++i) {
        output << "revocation.revoke_" << users[static_cast<std::size_t>(i)].gid
               << ".gid=" << users[static_cast<std::size_t>(i)].gid << '\n';
    }
}

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    CliArgs cli(argc, argv);

    const int user_count = std::stoi(cli.Get("--users", "20"));
    const int bundle_count = std::stoi(cli.Get("--bundles", "100"));
    const int keyword_pool_count = std::stoi(cli.Get("--keyword-pool", "200"));
    const int keywords_per_bundle = std::stoi(cli.Get("--keywords-per-bundle", "50"));
    const int attribute_pool_count = std::stoi(cli.Get("--attribute-pool", "50"));
    const int attributes_per_user = std::stoi(cli.Get("--attrs-per-user", "20"));
    const int attributes_per_policy = std::stoi(cli.Get("--attrs-per-policy", "10"));
    const auto query_sizes = ParseIntList(cli.Get("--query-sizes", "10,20,50"));
    const int queries_per_size = std::stoi(cli.Get("--queries-per-size", "3"));
    const int revocation_count = std::stoi(cli.Get("--revocations", "3"));
    const std::string policy_type = cli.Get("--policy-type", "and");
    const int common_pool_count = std::stoi(cli.Get("--common-keywords", "20"));
    const int medium_pool_count = std::stoi(cli.Get("--medium-keywords", "60"));
    const int rare_pool_count = std::stoi(cli.Get("--rare-keywords", "80"));
    const int common_per_bundle_in = std::stoi(cli.Get("--common-per-bundle", "8"));
    const int medium_per_bundle_in = std::stoi(cli.Get("--medium-per-bundle", "20"));
    const int rare_per_bundle_in = std::stoi(cli.Get("--rare-per-bundle", "12"));
    const int selective_per_bundle_in = std::stoi(cli.Get("--selective-per-bundle", "10"));
    const int selective_cluster_span_in = std::stoi(cli.Get("--selective-cluster-span", "8"));
    const auto seed = static_cast<std::mt19937::result_type>(std::stoul(cli.Get("--seed", "1337")));
    const auto output_path =
        std::filesystem::path(cli.Get("--output", (WorkspaceRoot() / "config" / "synthetic_benchmark.conf").string()));

    if (user_count <= 0 || bundle_count <= 0 || keyword_pool_count <= 0 || attribute_pool_count <= 0 ||
        keywords_per_bundle <= 0 || attributes_per_user <= 0 || attributes_per_policy <= 0 ||
        queries_per_size <= 0 || revocation_count < 0) {
        throw std::invalid_argument("all count parameters must be positive, except revocations which may be zero");
    }
    if (keywords_per_bundle > keyword_pool_count) {
        throw std::invalid_argument("keywords-per-bundle cannot exceed keyword-pool");
    }
    if (common_pool_count < 0 || medium_pool_count < 0 || rare_pool_count < 0) {
        throw std::invalid_argument("keyword band sizes cannot be negative");
    }
    if (common_pool_count + medium_pool_count + rare_pool_count > keyword_pool_count) {
        throw std::invalid_argument("common+medium+rare keyword counts cannot exceed keyword-pool");
    }
    if (selective_cluster_span_in <= 0) {
        throw std::invalid_argument("selective-cluster-span must be positive");
    }
    if (attributes_per_user > attribute_pool_count) {
        throw std::invalid_argument("attrs-per-user cannot exceed attribute-pool");
    }
    if (attributes_per_policy > attributes_per_user) {
        throw std::invalid_argument("attrs-per-policy cannot exceed attrs-per-user");
    }
    if (query_sizes.empty()) {
        throw std::invalid_argument("query-sizes must contain at least one value");
    }
    const int max_query_size = *std::max_element(query_sizes.begin(), query_sizes.end());
    if (max_query_size > keywords_per_bundle) {
        throw std::invalid_argument("max query size cannot exceed keywords-per-bundle in exact-match benchmark mode");
    }

    std::size_t threshold = static_cast<std::size_t>(std::stoul(cli.Get(
        "--threshold",
        std::to_string(std::max(1, std::min(attributes_per_policy, std::max(1, attributes_per_policy / 2)))))));
    if (policy_type == "attribute") {
        threshold = 1;
    }
    if (policy_type == "threshold" && (threshold == 0 || threshold > static_cast<std::size_t>(attributes_per_policy))) {
        throw std::invalid_argument("threshold must be within attrs-per-policy");
    }

    std::mt19937 rng(seed);
    const auto keyword_pool = MakeKeywordPool(static_cast<std::size_t>(keyword_pool_count));
    const auto keyword_bands = SplitKeywordBands(keyword_pool,
                                                 static_cast<std::size_t>(common_pool_count),
                                                 static_cast<std::size_t>(medium_pool_count),
                                                 static_cast<std::size_t>(rare_pool_count));
    const auto attribute_pool = MakeAttributePool(static_cast<std::size_t>(attribute_pool_count));
    const std::size_t common_per_bundle =
        ClampQuota(common_per_bundle_in, static_cast<std::size_t>(keywords_per_bundle), "common-per-bundle");
    const std::size_t medium_per_bundle = ClampQuota(
        medium_per_bundle_in,
        static_cast<std::size_t>(keywords_per_bundle) - common_per_bundle,
        "medium-per-bundle");
    const std::size_t rare_per_bundle = ClampQuota(
        rare_per_bundle_in,
        static_cast<std::size_t>(keywords_per_bundle) - common_per_bundle - medium_per_bundle,
        "rare-per-bundle");
    const std::size_t selective_per_bundle = ClampQuota(
        selective_per_bundle_in,
        static_cast<std::size_t>(keywords_per_bundle) - common_per_bundle - medium_per_bundle - rare_per_bundle,
        "selective-per-bundle");

    std::vector<SyntheticUser> users;
    users.reserve(static_cast<std::size_t>(user_count));
    for (int i = 1; i <= user_count; ++i) {
        SyntheticUser user;
        user.gid = "user_" + PadNumber(static_cast<std::size_t>(i));
        user.identity_secret = 1000 + i;
        user.attributes = SampleWithoutReplacement(attribute_pool, static_cast<std::size_t>(attributes_per_user), rng);
        users.push_back(std::move(user));
    }

    std::vector<SyntheticBundle> bundles;
    bundles.reserve(static_cast<std::size_t>(bundle_count));
    for (int i = 1; i <= bundle_count; ++i) {
        SyntheticBundle bundle;
        const auto& owner = users[static_cast<std::size_t>((i - 1) % user_count)];
        bundle.label = "bundle_" + PadNumber(static_cast<std::size_t>(i));
        bundle.owner_gid = owner.gid;
        bundle.plaintext = "synthetic_plaintext_" + std::to_string(i);
        bundle.keywords = BuildBundleKeywords(keyword_bands,
                                              static_cast<std::size_t>(i - 1),
                                              static_cast<std::size_t>(bundle_count),
                                              static_cast<std::size_t>(keywords_per_bundle),
                                              common_per_bundle,
                                              medium_per_bundle,
                                              rare_per_bundle,
                                              selective_per_bundle,
                                              static_cast<std::size_t>(selective_cluster_span_in),
                                              rng);
        bundle.policy_attributes =
            SampleWithoutReplacement(owner.attributes, static_cast<std::size_t>(attributes_per_policy), rng);
        bundle.policy_expression = MakePolicyExpression(policy_type, bundle.policy_attributes, threshold);
        const auto logical_policy = BuildLogicalPolicyFromParts(policy_type, bundle.policy_attributes, threshold);
        for (const auto& user : users) {
            if (PolicySatisfied(user.attributes, logical_policy)) {
                bundle.authorized_gids.push_back(user.gid);
            }
        }
        if (bundle.authorized_gids.empty()) {
            bundle.authorized_gids.push_back(owner.gid);
        }
        bundles.push_back(std::move(bundle));
    }

    WriteScenarioFile(output_path, users, bundles, query_sizes, queries_per_size, revocation_count, rng);

    std::cout << "Synthetic scenario written to " << output_path << '\n';
    std::cout << "Users: " << users.size()
              << ", bundles: " << bundles.size()
              << ", keyword pool: " << keyword_pool.size()
              << ", attributes: " << attribute_pool.size() << '\n';
    std::cout << "Keyword bands: common=" << keyword_bands.common.size()
              << ", medium=" << keyword_bands.medium.size()
              << ", rare=" << keyword_bands.rare.size()
              << ", selective=" << keyword_bands.selective.size() << '\n';
    std::cout << "Keywords per bundle: " << keywords_per_bundle
              << " (common=" << common_per_bundle
              << ", medium=" << medium_per_bundle
              << ", rare=" << rare_per_bundle
              << ", selective=" << selective_per_bundle << ")"
              << ", attrs per user: " << attributes_per_user
              << ", attrs per policy: " << attributes_per_policy << '\n';
    std::cout << "Query sizes: " << JoinStrings(query_sizes)
              << ", queries per size: " << queries_per_size
              << ", revocations: " << revocation_count << '\n';
    return 0;
}
