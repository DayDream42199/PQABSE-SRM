#include <iostream>

#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    std::string revoked_gid;
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
    if (!cli.Get("--revocation").empty()) {
        const auto scenario = LoadTestScenario(cli.Get("--scenario", DefaultScenarioPath().string()));
        revoked_gid = GetScenarioRevocation(scenario, cli.Get("--revocation")).gid;
    } else {
        revoked_gid = cli.Require("--gid");
    }

    IdentityAuthority ia;
    const auto phase_start = Clock::now();
    const auto revoke_start = Clock::now();
    if (!ia.revoke_user(revoked_gid)) { std::cerr << "Failed to revoke user " << revoked_gid << std::endl; return 1; }
    const double revoke_ms = ElapsedMilliseconds(revoke_start, Clock::now());
    TrustedAuthority ta;
    Blockchain.sync_from_chain();
    UserRecord revoked_user;
    if (!ia.get_user_record(revoked_gid, revoked_user)) { std::cerr << "Revoked user record missing" << std::endl; return 2; }
    ReEncryptionMaterial material;
    const auto rekey_start = Clock::now();
    if (!ta.generate_re_encryption_material(revoked_user, Blockchain.current_state.epoch, material)) { std::cerr << "Failed to derive re-encryption material" << std::endl; return 3; }
    const double rekey_material_ms = ElapsedMilliseconds(rekey_start, Clock::now());
    CloudRekeyState cloud_state{material.new_epoch, material.re_encryption_key, material.update_token, revoked_gid};
    SaveCloudRekeyState(cloud_state);
    const auto token_write_start = Clock::now();
    uintmax_t update_token_bytes = 0;
    int active_user_count = 0;
    for (const auto& user : ia.list_user_records()) {
        if (user.is_revoked) continue;
        ++active_user_count;
        std::string update_token;
        if (ta.generate_update_token_for_user(user, Blockchain.current_state.epoch, material.update_token, update_token)) {
            const auto token_path = UpdateTokenPath(user.user_gid, Blockchain.current_state.epoch);
            WriteTextFile(token_path, update_token);
            update_token_bytes += FileSizeOrZero(token_path);
        }
    }
    const double update_token_write_ms = ElapsedMilliseconds(token_write_start, Clock::now());
    AppendExperimentRow(metrics_path,
                        metrics_header,
                        {
                            ToCsvField("phase5_revoke"),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(revoked_gid),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(Blockchain.current_state.epoch),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(active_user_count),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(revoke_ms),
                            ToCsvField(rekey_material_ms),
                            ToCsvField(update_token_write_ms),
                            ToCsvField(ElapsedMilliseconds(phase_start, Clock::now())),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(""),
                            ToCsvField(FileSizeOrZero(CloudRekeyStatePath())),
                            ToCsvField(update_token_bytes)
                        });
    std::cout << "Revocation complete for " << revoked_gid << std::endl;
    std::cout << "Re-encryption key: " << material.re_encryption_key << std::endl;
    std::cout << "Update token seed: " << material.update_token << std::endl;
    return 0;
}
