#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

#include "entities/NitroTeeClient.h"
#include "entities/SoftwareTee.h"
#include "phase2_keygen.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "system/ExperimentMetrics.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

namespace {
int random_mod_q() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 12288);
    return dist(rng);
}

abse_zkp::NitroTeeOptions LoadNitroOptions(const abse_zkp::CliArgs& cli) {
    abse_zkp::NitroTeeOptions options;
    options.enclave_cid = static_cast<std::uint32_t>(std::stoul(cli.Get("--nitro-cid", "16")));
    options.port = static_cast<std::uint32_t>(std::stoul(cli.Get("--nitro-port", "5005")));
    options.timeout_ms = std::stoi(cli.Get("--nitro-timeout-ms", "30000"));
    return options;
}

bool WriteTimingFile(const std::string& path_value, double duration_ms) {
    if (path_value.empty()) {
        return true;
    }
    std::ostringstream output;
    output << std::fixed << std::setprecision(3) << duration_ms;
    return abse_zkp::WriteTextFile(path_value, output.str());
}
}

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    std::string gid;
    std::vector<std::string> attrs;
    int identity_secret = 0;
    double keygen_ms = 0.0;
    const auto timing_out = cli.Get("--timing-out");

    if (!cli.Get("--user").empty()) {
        const auto scenario = LoadTestScenario(cli.Get("--scenario", DefaultScenarioPath().string()));
        const auto& user_input = GetScenarioUser(scenario, cli.Get("--user"));
        gid = user_input.gid;
        attrs = user_input.attributes;
        identity_secret = user_input.has_identity_secret ? user_input.identity_secret : random_mod_q();
    } else {
        gid = cli.Require("--gid");
        attrs = cli.GetAll("--attr");
        if (attrs.empty()) attrs = {"default"};
        identity_secret = cli.Get("--identity-secret").empty() ? random_mod_q() : std::stoi(cli.Get("--identity-secret"));
    }
    const bool refresh_existing = cli.HasFlag("--refresh-existing");

    SystemParams params{};
    PK pk; MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) { std::cerr << "Failed to load Phase 1 artifacts" << std::endl; return 1; }
    IdentityAuthority ia;
    Blockchain.sync_from_chain();
    const bool use_nitro = cli.Get("--tee-mode", "software") == "nitro";
    const auto nitro_options = LoadNitroOptions(cli);
    SoftwareTee tee;
    NitroTeeClient nitro_tee;
    UserSecretKey user_key;

    if (refresh_existing) {
        UserRecord user_record;
        if (!ia.get_user_record(gid, user_record)) { std::cerr << "User is not registered with IA: " << gid << std::endl; return 2; }
        if (user_record.is_revoked) { std::cerr << "Cannot refresh key for revoked user " << gid << std::endl; return 3; }

        UserCredentialRecord record;
        if (!LoadUserCredentialRecord(gid, record)) {
            std::cerr << "Failed to load credential record for " << gid << std::endl;
            return 7;
        }
        identity_secret = record.identity_secret;

        CloudRekeyState rekey_state;
        if (!LoadCloudRekeyState(rekey_state) || rekey_state.epoch != Blockchain.current_state.epoch) {
            std::cerr << "Missing current cloud rekey state for epoch " << Blockchain.current_state.epoch << std::endl;
            return 4;
        }

        const bool needs_update_token = record.local_epoch < Blockchain.current_state.epoch;
        if (!needs_update_token) {
            UserSecretKey existing_key;
            if (!LoadUserSecretKey(params, existing_key, record.user_key_path)) {
                std::cerr << "Failed to load existing user key for " << gid << std::endl;
                return 8;
            }
            if (rekey_state.update_token_seed.empty() || existing_key.update_seed == rekey_state.update_token_seed) {
                std::cout << "User key already current for " << gid << std::endl;
                return 0;
            }
        }

        TrustedAuthority ta;
        std::string expected_token;
        if (needs_update_token) {
            if (!ta.generate_update_token_for_user(user_record, Blockchain.current_state.epoch, rekey_state.update_token_seed, expected_token)) {
                std::cerr << "Failed to derive expected update token" << std::endl;
                return 5;
            }

            std::string provided_token;
            if (!ReadTextFile(UpdateTokenPath(gid, Blockchain.current_state.epoch), provided_token) || provided_token != expected_token) {
                std::cerr << "Missing or invalid update token for user " << gid << std::endl;
                return 6;
            }
        }

        const auto keygen_start = Clock::now();
        if (use_nitro) {
            nitro_tee.GenerateUserKey(params,
                                      pk,
                                      msk,
                                      gid,
                                      attrs,
                                      user_key,
                                      Blockchain.current_state.epoch,
                                      rekey_state.update_token_seed,
                                      nitro_options);
        } else {
            tee.GenerateUserKey(params, pk, msk, gid, attrs, user_key, Blockchain.current_state.epoch, rekey_state.update_token_seed);
        }
        keygen_ms = ElapsedMilliseconds(keygen_start, Clock::now());
        if (!SaveUserSecretKey(params, user_key, record.user_key_path)) { std::cerr << "Failed to save refreshed user key" << std::endl; return 8; }
        record.local_epoch = Blockchain.current_state.epoch;
        record.attributes = user_key.attributes;
        if (!SaveUserCredentialRecord(record)) { std::cerr << "Failed to update user credential record" << std::endl; return 9; }
        if (!WriteTimingFile(timing_out, keygen_ms)) {
            std::cerr << "Failed to write keygen timing output" << std::endl;
            return 10;
        }
        std::cout << "Phase 2 key refresh complete for " << gid << std::endl;
        std::cout << "Keygen ms: " << std::fixed << std::setprecision(3) << keygen_ms << std::endl;
        return 0;
    }

    CloudRekeyState registration_rekey_state;
    std::string registration_update_seed;
    if (Blockchain.current_state.epoch > 0) {
        if (!LoadCloudRekeyState(registration_rekey_state) ||
            registration_rekey_state.epoch != Blockchain.current_state.epoch) {
            std::cerr << "Missing current cloud rekey state for epoch " << Blockchain.current_state.epoch << std::endl;
            return 4;
        }
        registration_update_seed = registration_rekey_state.update_token_seed;
    }

    ia.register_user(gid, identity_secret);
    const auto keygen_start = Clock::now();
    if (use_nitro) {
        nitro_tee.GenerateUserKey(params,
                                  pk,
                                  msk,
                                  gid,
                                  attrs,
                                  user_key,
                                  Blockchain.current_state.epoch,
                                  registration_update_seed,
                                  nitro_options);
    } else {
        tee.GenerateUserKey(params, pk, msk, gid, attrs, user_key, Blockchain.current_state.epoch, registration_update_seed);
    }
    keygen_ms = ElapsedMilliseconds(keygen_start, Clock::now());
    if (!SaveUserSecretKey(params, user_key, UserSecretKeyPath(gid).string())) { std::cerr << "Failed to save user key" << std::endl; return 10; }
    UserCredentialRecord record{gid, identity_secret, Blockchain.current_state.epoch, UserSecretKeyPath(gid).string(), user_key.attributes};
    if (!SaveUserCredentialRecord(record)) { std::cerr << "Failed to save user credential record" << std::endl; return 11; }
    if (!registration_update_seed.empty()) {
        UserRecord user_record;
        if (!ia.get_user_record(gid, user_record)) {
            std::cerr << "Failed to load registered user record for " << gid << std::endl;
            return 12;
        }
        TrustedAuthority ta;
        std::string update_token;
        if (!ta.generate_update_token_for_user(user_record, Blockchain.current_state.epoch, registration_update_seed, update_token)) {
            std::cerr << "Failed to derive update token for newly registered user " << gid << std::endl;
            return 13;
        }
        if (!WriteTextFile(UpdateTokenPath(gid, Blockchain.current_state.epoch), update_token)) {
            std::cerr << "Failed to persist update token for newly registered user " << gid << std::endl;
            return 14;
        }
    }
    if (!WriteTimingFile(timing_out, keygen_ms)) {
        std::cerr << "Failed to write keygen timing output" << std::endl;
        return 15;
    }
    std::cout << "Phase 2 key generation complete for " << gid << std::endl;
    std::cout << "Keygen ms: " << std::fixed << std::setprecision(3) << keygen_ms << std::endl;
    return 0;
}
