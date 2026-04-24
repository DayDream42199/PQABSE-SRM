#include <algorithm>
#include <filesystem>
#include <iostream>
#include <map>
#include <numeric>
#include <string>
#include <vector>

#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/ExperimentMetrics.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

namespace {

using namespace abse_zkp;

template <typename T>
double AverageOrZero(const std::vector<T>& values) {
    if (values.empty()) {
        return 0.0;
    }
    const double sum = std::accumulate(values.begin(), values.end(), 0.0);
    return sum / static_cast<double>(values.size());
}

struct AggregateBucket {
    int active_user_count = 0;
    int runs = 0;
    std::vector<double> revoke_ms;
    std::vector<double> rekey_material_ms;
    std::vector<double> update_token_write_ms;
    std::vector<double> cloud_rekey_bytes;
    std::vector<double> update_token_bytes;
};

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const auto scenario_path = std::filesystem::path(cli.Get("--scenario", DefaultScenarioPath().string()));
    const auto metrics_path =
        cli.Get("--metrics-out", (ExperimentArtifactRoot() / "revocation_benchmark_sweep.csv").string());
    const auto aggregate_path =
        cli.Get("--aggregate-out", (ExperimentArtifactRoot() / "revocation_benchmark_sweep_aggregate.csv").string());
    const int limit = std::stoi(cli.Get("--limit", "0"));

    const std::vector<std::string> metrics_header = {
        "phase", "revocation_name", "revoked_gid", "epoch", "active_user_count",
        "revoke_ms", "rekey_material_ms", "update_token_write_ms",
        "phase_total_ms", "cloud_rekey_bytes", "update_token_bytes", "avg_update_token_bytes"
    };
    const std::vector<std::string> aggregate_header = {
        "phase", "active_user_count", "runs", "avg_revoke_ms", "avg_rekey_material_ms",
        "avg_update_token_write_ms", "avg_cloud_rekey_bytes", "avg_update_token_bytes"
    };

    const auto scenario = LoadTestScenario(scenario_path);
    IdentityAuthority ia;
    std::map<int, AggregateBucket> aggregates;

    int processed = 0;
    for (const auto& [revocation_name, revocation] : scenario.revocations) {
        if (limit > 0 && processed >= limit) {
            break;
        }

        UserRecord target_record;
        if (!ia.get_user_record(revocation.gid, target_record)) {
            std::cerr << "Skipping revocation " << revocation_name << ": unknown user " << revocation.gid << std::endl;
            continue;
        }
        if (target_record.is_revoked) {
            std::cerr << "Skipping revocation " << revocation_name << ": user already revoked " << revocation.gid << std::endl;
            continue;
        }

        const auto phase_start = Clock::now();
        int active_user_count = 0;
        for (const auto& user : ia.list_user_records()) {
            if (!user.is_revoked) {
                ++active_user_count;
            }
        }

        const auto revoke_start = Clock::now();
        if (!ia.revoke_user(revocation.gid)) {
            std::cerr << "Failed to revoke user " << revocation.gid << std::endl;
            return 1;
        }
        const double revoke_ms = ElapsedMilliseconds(revoke_start, Clock::now());

        TrustedAuthority ta;
        Blockchain.sync_from_chain();
        UserRecord revoked_user;
        if (!ia.get_user_record(revocation.gid, revoked_user)) {
            std::cerr << "Revoked user record missing for " << revocation.gid << std::endl;
            return 2;
        }

        ReEncryptionMaterial material;
        const auto rekey_start = Clock::now();
        if (!ta.generate_re_encryption_material(revoked_user, Blockchain.current_state.epoch, material)) {
            std::cerr << "Failed to derive re-encryption material for " << revocation.gid << std::endl;
            return 3;
        }
        const double rekey_material_ms = ElapsedMilliseconds(rekey_start, Clock::now());

        CloudRekeyState cloud_state{material.new_epoch, material.re_encryption_key, material.update_token, revocation.gid};
        if (!SaveCloudRekeyState(cloud_state)) {
            std::cerr << "Failed to persist cloud rekey state" << std::endl;
            return 4;
        }

        const auto token_write_start = Clock::now();
        uintmax_t update_token_bytes = 0;
        int current_active_users = 0;
        for (const auto& user : ia.list_user_records()) {
            if (user.is_revoked) {
                continue;
            }
            ++current_active_users;
            std::string update_token;
            if (ta.generate_update_token_for_user(user, Blockchain.current_state.epoch, material.update_token, update_token)) {
                const auto token_path = UpdateTokenPath(user.user_gid, Blockchain.current_state.epoch);
                WriteTextFile(token_path, update_token);
                update_token_bytes += FileSizeOrZero(token_path);
            }
        }
        const double update_token_write_ms = ElapsedMilliseconds(token_write_start, Clock::now());
        const double phase_total_ms = ElapsedMilliseconds(phase_start, Clock::now());
        const double avg_update_token_bytes =
            current_active_users > 0 ? static_cast<double>(update_token_bytes) / static_cast<double>(current_active_users) : 0.0;

        AppendExperimentRow(metrics_path,
                            metrics_header,
                            {
                                ToCsvField("revocation_benchmark_sweep"),
                                ToCsvField(revocation_name),
                                ToCsvField(revocation.gid),
                                ToCsvField(Blockchain.current_state.epoch),
                                ToCsvField(active_user_count),
                                ToCsvField(revoke_ms),
                                ToCsvField(rekey_material_ms),
                                ToCsvField(update_token_write_ms),
                                ToCsvField(phase_total_ms),
                                ToCsvField(FileSizeOrZero(CloudRekeyStatePath())),
                                ToCsvField(update_token_bytes),
                                ToCsvField(avg_update_token_bytes)
                            });

        auto& bucket = aggregates[active_user_count];
        bucket.active_user_count = active_user_count;
        ++bucket.runs;
        bucket.revoke_ms.push_back(revoke_ms);
        bucket.rekey_material_ms.push_back(rekey_material_ms);
        bucket.update_token_write_ms.push_back(update_token_write_ms);
        bucket.cloud_rekey_bytes.push_back(static_cast<double>(FileSizeOrZero(CloudRekeyStatePath())));
        bucket.update_token_bytes.push_back(static_cast<double>(update_token_bytes));
        ++processed;
    }

    for (const auto& [active_user_count, bucket] : aggregates) {
        AppendExperimentRow(aggregate_path,
                            aggregate_header,
                            {
                                ToCsvField("revocation_benchmark_sweep_aggregate"),
                                ToCsvField(active_user_count),
                                ToCsvField(bucket.runs),
                                ToCsvField(AverageOrZero(bucket.revoke_ms)),
                                ToCsvField(AverageOrZero(bucket.rekey_material_ms)),
                                ToCsvField(AverageOrZero(bucket.update_token_write_ms)),
                                ToCsvField(AverageOrZero(bucket.cloud_rekey_bytes)),
                                ToCsvField(AverageOrZero(bucket.update_token_bytes))
                            });
    }

    std::cout << "Revocation benchmark sweep complete for " << processed << " revocation event(s)." << '\n';
    for (const auto& [active_user_count, bucket] : aggregates) {
        std::cout << "active_users=" << active_user_count
                  << " runs=" << bucket.runs
                  << " avg_revoke_ms=" << AverageOrZero(bucket.revoke_ms)
                  << " avg_tokens_bytes=" << AverageOrZero(bucket.update_token_bytes) << '\n';
    }
    return 0;
}
