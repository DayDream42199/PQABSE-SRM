#include <iostream>

#include "entities/SearchGateway.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "pq_src/User.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    std::string gid;
    std::string label;
    std::vector<std::string> query_keywords;
    const auto metrics_path = cli.Get("--metrics-out", DefaultExperimentMetricsPath().string());
    const std::vector<std::string> metrics_header = {
        "phase", "gid", "owner_gid", "revoked_gid", "preferred_label", "matched_label", "bundle_label",
        "epoch", "keyword_count", "query_keyword_count", "candidate_count", "active_user_count",
        "cache_hit", "search_success", "encrypt_bundle_ms", "mobile_encrypt_ms", "bundle_write_ms", "index_update_ms",
        "trapdoor_gen_ms", "auth_verify_ms", "index_prepare_ms", "candidate_prune_ms",
        "retrieve_decrypt_ms", "revoke_ms", "rekey_material_ms", "update_token_write_ms",
        "phase_total_ms", "bundle_bytes", "bundle_meta_bytes", "bitmap_index_bytes",
        "cloud_rekey_bytes", "update_token_bytes"
    };

    if (!cli.Get("--query").empty()) {
        const auto scenario = LoadTestScenario(cli.Get("--scenario", DefaultScenarioPath().string()));
        const auto& query = GetScenarioQuery(scenario, cli.Get("--query"));
        gid = query.gid;
        label = query.bundle_label;
        query_keywords = query.keywords;
    } else {
        gid = cli.Require("--gid");
        label = cli.Get("--label");
        query_keywords = cli.GetAll("--query-keyword");
        if (query_keywords.empty()) query_keywords = {"default"};
    }
    const auto phase_start = Clock::now();
    double trapdoor_gen_ms = 0.0;
    auto write_metrics = [&](const SearchGateway& gateway,
                             bool success,
                             const std::string& matched_label,
                             const std::filesystem::path& bundle_path) {
        AppendExperimentRow(metrics_path,
                            metrics_header,
                            {
                                ToCsvField("phase4_search"),
                                ToCsvField(gid),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(label),
                                ToCsvField(matched_label),
                                ToCsvField(matched_label),
                                ToCsvField(Blockchain.current_state.epoch),
                                ToCsvField(""),
                                ToCsvField(static_cast<uint64_t>(query_keywords.size())),
                                ToCsvField(static_cast<uint64_t>(gateway.last_candidate_labels().size())),
                                ToCsvField(""),
                                ToCsvField(gateway.last_search_index_cache_hit()),
                                ToCsvField(success),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(trapdoor_gen_ms),
                                ToCsvField(gateway.last_verify_time_ms()),
                                ToCsvField(gateway.last_index_prepare_time_ms()),
                                ToCsvField(gateway.last_candidate_prune_time_ms()),
                                ToCsvField(gateway.last_retrieve_decrypt_time_ms()),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(""),
                                ToCsvField(ElapsedMilliseconds(phase_start, Clock::now())),
                                ToCsvField(FileSizeOrZero(bundle_path)),
                                ToCsvField(bundle_path.empty() ? 0 : FileSizeOrZero(BundleMetaPath(matched_label))),
                                ToCsvField(FileSizeOrZero(SearchArtifactRoot() / ("bitmap_index_epoch_" + std::to_string(Blockchain.current_state.epoch) + ".bin"))),
                                ToCsvField(""),
                                ToCsvField("")
                            });
    };

    IdentityAuthority ia;
    Blockchain.sync_from_chain();
    CloudRekeyState rekey_state;
    LoadCloudRekeyState(rekey_state);
    UserCredentialRecord credential;
    if (!LoadUserCredentialRecord(gid, credential)) { std::cerr << "Failed to load credential for " << gid << std::endl; return 1; }
    UserRecord user_record;
    if (!ia.get_user_record(gid, user_record)) { std::cerr << "User is not registered with IA: " << gid << std::endl; return 2; }
    std::string provided_token;
    if (!rekey_state.update_token_seed.empty()) {
        TrustedAuthority ta;
        std::string expected_token;
        if (!ta.generate_update_token_for_user(user_record, Blockchain.current_state.epoch, rekey_state.update_token_seed, expected_token)) { std::cerr << "Failed to derive expected update token" << std::endl; return 3; }
        if (!ReadTextFile(UpdateTokenPath(gid, Blockchain.current_state.epoch), provided_token) || provided_token != expected_token) { std::cerr << "Missing or invalid update token for user " << gid << std::endl; return 4; }
    }
    if (credential.local_epoch != Blockchain.current_state.epoch) {
        std::cerr << "User key update required for user " << gid << std::endl;
        return 5;
    }

    SystemParams params{}; PK pk; MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) { std::cerr << "Failed to load Phase 1 artifacts" << std::endl; return 5; }
    UserSecretKey user_key;
    if (!LoadUserSecretKey(params, user_key, credential.user_key_path)) { std::cerr << "Failed to load user secret key" << std::endl; return 6; }
    if (user_key.epoch != Blockchain.current_state.epoch) { std::cerr << "User secret key is stale for user " << gid << std::endl; return 7; }
    if (!rekey_state.update_token_seed.empty() && user_key.update_seed != rekey_state.update_token_seed) { std::cerr << "User secret key update seed mismatch for user " << gid << std::endl; return 8; }
    User user(gid, credential.identity_secret, true);
    const auto trapdoor_start = Clock::now();
    if (!user.request_zkp_authentication(ia)) { std::cerr << "Failed to obtain proof-backed authentication token" << std::endl; return 9; }
    trapdoor_gen_ms = ElapsedMilliseconds(trapdoor_start, Clock::now());
    SearchGateway gateway(ia);
    if (!gateway.VerifyAuthToken(user.get_auth_token())) { std::cerr << "Authentication token verification failed" << std::endl; return 10; }
    StoredBundleRecord bundle_record;
    CiphertextBundle bundle;
    SearchResult result;
    if (!gateway.SearchAndRetrieve(params, user_key, user_record, provided_token, query_keywords, label, rekey_state, bundle_record, bundle, result)) {
        std::cerr << "Search or decrypt failed" << std::endl;
        if (!gateway.last_candidate_labels().empty()) {
            std::cerr << "Candidate bundles:";
            for (const auto& candidate : gateway.last_candidate_labels()) std::cerr << ' ' << candidate;
            std::cerr << std::endl;
        }
        write_metrics(gateway, false, "", {});
        return 11;
    }
    SaveStoredBundleRecord(bundle_record);
    write_metrics(gateway, true, bundle_record.bundle_label, bundle_record.bundle_path);
    std::cout << "Bundle: " << bundle_record.bundle_label << '\n';
    if (!gateway.last_candidate_labels().empty()) {
        std::cout << "Candidate bundles:";
        for (const auto& candidate : gateway.last_candidate_labels()) std::cout << ' ' << candidate;
        std::cout << '\n';
    }
    std::cout << "Matched keywords:"; for (const auto& keyword : result.matched_keywords) std::cout << ' ' << keyword; std::cout << '\n';
    std::cout << "Plaintext:\n" << result.plaintext << std::endl;
    return 0;
}
