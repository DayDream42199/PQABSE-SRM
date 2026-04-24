#include <iostream>
#include <random>

#include "entities/SoftwareTee.h"
#include "phase1_setup.h"
#include "phase2_keygen.h"
#include "phase3_encrypt.h"
#include "phase4_search.h"
#include "pq_src/Blockchain.h"
#include "pq_src/IdentityAuthority.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

namespace {

int random_mod_q() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 12288);
    return dist(rng);
}

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const auto scenario_path = std::filesystem::path(cli.Get("--scenario", DefaultScenarioPath().string()));
    const auto metrics_path =
        std::filesystem::path(cli.Get("--metrics-out", (ExperimentArtifactRoot() / "core_crypto_benchmark.csv").string()));
    const bool init_phase1_if_missing = cli.HasFlag("--init-phase1-if-missing");

    const std::vector<std::string> metrics_header = {
        "phase", "scenario_user", "scenario_bundle", "scenario_query", "gid", "bundle_label", "epoch",
        "attribute_count", "policy_attribute_count", "keyword_count", "keygen_ms", "encrypt_bundle_ms",
        "trapdoor_gen_ms", "decrypt_ms", "phase_total_ms", "user_key_bytes", "ciphertext_bytes",
        "ciphertext_meta_bytes", "plaintext_recovered"
    };

    std::string scenario_user_name = cli.Get("--user");
    std::string scenario_bundle_name = cli.Get("--bundle");
    std::string scenario_query_name = cli.Get("--query");
    std::string gid = cli.Get("--gid");
    std::string bundle_label = cli.Get("--label");
    std::vector<std::string> attributes = cli.GetAll("--attr");
    std::vector<std::string> keywords = cli.GetAll("--keyword");
    std::vector<std::string> query_keywords = cli.GetAll("--query-keyword");
    std::string plaintext = cli.Get("--plaintext");
    LogicalPolicy logical_policy = BuildLogicalPolicyFromParts("and", {"default"}, 1);
    int identity_secret = cli.Get("--identity-secret").empty() ? random_mod_q() : std::stoi(cli.Get("--identity-secret"));

    if (!scenario_query_name.empty() || !scenario_bundle_name.empty() || !scenario_user_name.empty()) {
        const auto scenario = LoadTestScenario(scenario_path);
        if (!scenario_query_name.empty()) {
            const auto& query = GetScenarioQuery(scenario, scenario_query_name);
            gid = query.gid;
            bundle_label = query.bundle_label;
            query_keywords = query.keywords;
        }
        if (!scenario_bundle_name.empty()) {
            const auto& bundle_input = GetScenarioBundle(scenario, scenario_bundle_name);
            bundle_label = bundle_input.label;
            plaintext = bundle_input.plaintext;
            keywords = bundle_input.keywords;
            logical_policy = bundle_input.policy;
        }
        if (!scenario_user_name.empty()) {
            const auto& user_input = GetScenarioUser(scenario, scenario_user_name);
            gid = user_input.gid;
            attributes = user_input.attributes;
            if (user_input.has_identity_secret) {
                identity_secret = user_input.identity_secret;
            }
        }
        if (attributes.empty() && !gid.empty()) {
            for (const auto& [name, user_input] : scenario.users) {
                if (user_input.gid == gid) {
                    scenario_user_name = name;
                    attributes = user_input.attributes;
                    if (user_input.has_identity_secret) {
                        identity_secret = user_input.identity_secret;
                    }
                    break;
                }
            }
        }
        if (plaintext.empty() && !bundle_label.empty()) {
            for (const auto& [name, bundle_input] : scenario.bundles) {
                if (bundle_input.label == bundle_label) {
                    scenario_bundle_name = name;
                    plaintext = bundle_input.plaintext;
                    keywords = bundle_input.keywords;
                    logical_policy = bundle_input.policy;
                    break;
                }
            }
        }
    } else {
        if (gid.empty()) gid = cli.Require("--gid");
        if (bundle_label.empty()) bundle_label = cli.Require("--label");
        if (plaintext.empty()) plaintext = cli.Require("--plaintext");
        if (keywords.empty()) keywords = {"default"};
        if (query_keywords.empty()) query_keywords = keywords;
        if (attributes.empty()) attributes = {"default"};
        const std::string policy_expression = cli.Get("--policy");
        if (!policy_expression.empty()) {
            logical_policy = BuildLogicalPolicyFromExpression(policy_expression);
        } else {
            const std::string policy_type = cli.Get("--policy-type", "and");
            auto policy_attrs = cli.GetAll("--policy-attr");
            if (policy_attrs.empty()) policy_attrs = attributes;
            const std::size_t threshold = static_cast<std::size_t>(std::stoull(cli.Get("--threshold", "1")));
            logical_policy = BuildLogicalPolicyFromParts(policy_type, policy_attrs, threshold);
        }
    }

    if (gid.empty() || bundle_label.empty() || plaintext.empty() || attributes.empty() || keywords.empty() || query_keywords.empty()) {
        std::cerr << "core_crypto_benchmark requires a complete user, bundle, and query input set" << std::endl;
        return 1;
    }

    const auto phase_start = Clock::now();
    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        if (!init_phase1_if_missing) {
            std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
            return 2;
        }
        InitSystemParams(params, 256, 12289, 3.2, 2, false);
        Setup(params, pk, msk);
        if (!SavePhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
            std::cerr << "Failed to initialize Phase 1 artifacts" << std::endl;
            return 3;
        }
    }

    IdentityAuthority ia;
    Blockchain.sync_from_chain();
    UserRecord existing_user;
    if (!ia.get_user_record(gid, existing_user)) {
        ia.register_user(gid, identity_secret);
    }

    SoftwareTee tee;
    UserSecretKey user_key;
    const auto keygen_start = Clock::now();
    tee.GenerateUserKey(params, pk, msk, gid, attributes, user_key, Blockchain.current_state.epoch, "");
    const double keygen_ms = ElapsedMilliseconds(keygen_start, Clock::now());
    const auto user_key_path = UserSecretKeyPath(gid);
    if (!SaveUserSecretKey(params, user_key, user_key_path.string())) {
        std::cerr << "Failed to save user key for benchmark user " << gid << std::endl;
        return 4;
    }
    UserCredentialRecord credential{gid, identity_secret, Blockchain.current_state.epoch, user_key_path.string(), attributes};
    if (!SaveUserCredentialRecord(credential)) {
        std::cerr << "Failed to save benchmark credential for " << gid << std::endl;
        return 5;
    }

    CiphertextBundle bundle;
    const auto encrypt_start = Clock::now();
    tee.CreateCiphertextBundle(params,
                               pk,
                               bundle_label,
                               plaintext,
                               keywords,
                               logical_policy,
                               "epoch-" + std::to_string(Blockchain.current_state.epoch),
                               bundle);
    const double encrypt_bundle_ms = ElapsedMilliseconds(encrypt_start, Clock::now());
    const auto bundle_path = BundleBinaryPath(bundle_label);
    if (!SaveCiphertextBundle(params, bundle, bundle_path.string())) {
        std::cerr << "Failed to save benchmark bundle " << bundle_label << std::endl;
        return 6;
    }

    StoredBundleRecord bundle_record;
    bundle_record.bundle_label = bundle_label;
    bundle_record.bundle_path = bundle_path.string();
    bundle_record.data_owner_gid = gid;
    bundle_record.version_tag = Blockchain.current_state;
    if (!SaveStoredBundleRecord(bundle_record)) {
        std::cerr << "Failed to save benchmark bundle metadata for " << bundle_label << std::endl;
        return 7;
    }

    SearchTrapdoor trapdoor;
    const auto trapdoor_start = Clock::now();
    TrapGen(params, user_key, bundle.file_nonce, gid + "__" + bundle_label + "__core_benchmark", query_keywords, trapdoor);
    const double trapdoor_gen_ms = ElapsedMilliseconds(trapdoor_start, Clock::now());

    SearchResult result;
    const auto decrypt_start = Clock::now();
    const bool decrypt_ok = RetrieveAndDecrypt(params, user_key, bundle, trapdoor, result);
    const double decrypt_ms = ElapsedMilliseconds(decrypt_start, Clock::now());
    if (!decrypt_ok || !result.plaintext_recovered) {
        std::cerr << "Benchmark decrypt failed for bundle " << bundle_label << std::endl;
        return 8;
    }

    const auto policy = BuildAccessPolicy(logical_policy);
    std::size_t policy_attribute_count = 0;
    for (const auto& rho : policy.rho) {
        if (!rho.empty()) {
            ++policy_attribute_count;
        }
    }

    AppendExperimentRow(metrics_path,
                        metrics_header,
                        {
                            ToCsvField("core_crypto_benchmark"),
                            ToCsvField(scenario_user_name),
                            ToCsvField(scenario_bundle_name),
                            ToCsvField(scenario_query_name),
                            ToCsvField(gid),
                            ToCsvField(bundle_label),
                            ToCsvField(Blockchain.current_state.epoch),
                            ToCsvField(static_cast<uintmax_t>(attributes.size())),
                            ToCsvField(static_cast<uintmax_t>(policy_attribute_count)),
                            ToCsvField(static_cast<uintmax_t>(keywords.size())),
                            ToCsvField(keygen_ms),
                            ToCsvField(encrypt_bundle_ms),
                            ToCsvField(trapdoor_gen_ms),
                            ToCsvField(decrypt_ms),
                            ToCsvField(ElapsedMilliseconds(phase_start, Clock::now())),
                            ToCsvField(FileSizeOrZero(user_key_path)),
                            ToCsvField(FileSizeOrZero(bundle_path)),
                            ToCsvField(FileSizeOrZero(BundleMetaPath(bundle_label))),
                            ToCsvField(result.plaintext_recovered)
                        });

    std::cout << "Core crypto benchmark complete." << '\n';
    std::cout << "gid=" << gid
              << " bundle=" << bundle_label
              << " keygen_ms=" << keygen_ms
              << " encrypt_ms=" << encrypt_bundle_ms
              << " decrypt_ms=" << decrypt_ms
              << " user_key_bytes=" << FileSizeOrZero(user_key_path)
              << " ciphertext_bytes=" << FileSizeOrZero(bundle_path)
              << '\n';
    return 0;
}
