#include <iostream>
#include <random>

#include "entities/SoftwareTee.h"
#include "phase2_keygen.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
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
}

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    std::string gid;
    std::vector<std::string> attrs;
    int identity_secret = 0;

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
    SoftwareTee tee;
    UserSecretKey user_key;

    if (refresh_existing) {
        UserRecord user_record;
        if (!ia.get_user_record(gid, user_record)) { std::cerr << "User is not registered with IA: " << gid << std::endl; return 2; }
        if (user_record.is_revoked) { std::cerr << "Cannot refresh key for revoked user " << gid << std::endl; return 3; }

        CloudRekeyState rekey_state;
        if (!LoadCloudRekeyState(rekey_state) || rekey_state.epoch != Blockchain.current_state.epoch) {
            std::cerr << "Missing current cloud rekey state for epoch " << Blockchain.current_state.epoch << std::endl;
            return 4;
        }

        TrustedAuthority ta;
        std::string expected_token;
        if (!ta.generate_update_token_for_user(user_record, Blockchain.current_state.epoch, rekey_state.update_token_seed, expected_token)) {
            std::cerr << "Failed to derive expected update token" << std::endl;
            return 5;
        }

        std::string provided_token;
        if (!ReadTextFile(UpdateTokenPath(gid, Blockchain.current_state.epoch), provided_token) || provided_token != expected_token) {
            std::cerr << "Missing or invalid update token for user " << gid << std::endl;
            return 6;
        }

        UserCredentialRecord record;
        if (!LoadUserCredentialRecord(gid, record)) {
            std::cerr << "Failed to load credential record for " << gid << std::endl;
            return 7;
        }
        identity_secret = record.identity_secret;
        tee.GenerateUserKey(params, pk, msk, gid, attrs, user_key, Blockchain.current_state.epoch, rekey_state.update_token_seed);
        if (!SaveUserSecretKey(params, user_key, record.user_key_path)) { std::cerr << "Failed to save refreshed user key" << std::endl; return 8; }
        record.local_epoch = Blockchain.current_state.epoch;
        record.attributes = user_key.attributes;
        if (!SaveUserCredentialRecord(record)) { std::cerr << "Failed to update user credential record" << std::endl; return 9; }
        std::cout << "Phase 2 key refresh complete for " << gid << std::endl;
        return 0;
    }

    ia.register_user(gid, identity_secret);
    tee.GenerateUserKey(params, pk, msk, gid, attrs, user_key, Blockchain.current_state.epoch, "");
    if (!SaveUserSecretKey(params, user_key, UserSecretKeyPath(gid).string())) { std::cerr << "Failed to save user key" << std::endl; return 10; }
    UserCredentialRecord record{gid, identity_secret, Blockchain.current_state.epoch, UserSecretKeyPath(gid).string(), user_key.attributes};
    if (!SaveUserCredentialRecord(record)) { std::cerr << "Failed to save user credential record" << std::endl; return 11; }
    std::cout << "Phase 2 key generation complete for " << gid << std::endl;
    return 0;
}
