#include <iomanip>
#include <iostream>
#include <sstream>

#include "phase1_setup.h"
#include "phase2_keygen.h"
#include "phase4_search.h"
#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "pq_src/User.h"
#include "system/Artifacts.h"
#include "system/ExperimentMetrics.h"
#include "system/AuthTokenIO.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"
#include "system/TestScenario.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);
    const auto trapdoor_timing_out = cli.Get("--trapdoor-timing-out");

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
            query_keywords = {"default"};
        }
    }
    const auto request_dir = std::filesystem::path(cli.Require("--out-dir"));

    IdentityAuthority ia;
    Blockchain.sync_from_chain();
    CloudRekeyState rekey_state;
    LoadCloudRekeyState(rekey_state);

    UserCredentialRecord credential;
    if (!LoadUserCredentialRecord(gid, credential)) {
        std::cerr << "Failed to load credential for " << gid << std::endl;
        return 1;
    }
    if (credential.local_epoch != Blockchain.current_state.epoch) {
        std::cerr << "User key update required for user " << gid << std::endl;
        return 2;
    }

    UserRecord user_record;
    if (!ia.get_user_record(gid, user_record)) {
        std::cerr << "User is not registered with IA: " << gid << std::endl;
        return 3;
    }

    std::string provided_token;
    if (!rekey_state.update_token_seed.empty()) {
        TrustedAuthority ta;
        std::string expected_token;
        if (!ta.generate_update_token_for_user(user_record, Blockchain.current_state.epoch, rekey_state.update_token_seed, expected_token)) {
            std::cerr << "Failed to derive expected update token" << std::endl;
            return 4;
        }
        if (!ReadTextFile(UpdateTokenPath(gid, Blockchain.current_state.epoch), provided_token) || provided_token != expected_token) {
            std::cerr << "Missing or invalid update token for user " << gid << std::endl;
            return 5;
        }
    }

    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
        return 6;
    }

    UserSecretKey user_key;
    if (!LoadUserSecretKey(params, user_key, credential.user_key_path)) {
        std::cerr << "Failed to load user secret key" << std::endl;
        return 7;
    }

    User user(gid, credential.identity_secret, true);
    if (!user.request_zkp_authentication(ia)) {
        std::cerr << "Failed to obtain proof-backed authentication token" << std::endl;
        return 8;
    }

    SearchTrapdoor shortlist_trapdoor;
    std::array<unsigned char, 16> global_nonce{};
    const auto trapdoor_start = Clock::now();
    TrapGen(params, user_key, global_nonce, preferred_label, query_keywords, shortlist_trapdoor);
    const double trapdoor_gen_ms = ElapsedMilliseconds(trapdoor_start, Clock::now());

    std::filesystem::create_directories(request_dir);
    if (!SaveAuthToken(user.get_auth_token(), request_dir / "auth_token.txt")) {
        std::cerr << "Failed to write auth token" << std::endl;
        return 9;
    }
    if (!SaveSearchTrapdoor(params, shortlist_trapdoor, (request_dir / "shortlist_trapdoor.bin").string())) {
        std::cerr << "Failed to write shortlist trapdoor" << std::endl;
        return 10;
    }
    if (!WriteTextFile(request_dir / "preferred_label.txt", preferred_label)) {
        std::cerr << "Failed to write preferred label" << std::endl;
        return 11;
    }
    if (!WriteTextFile(request_dir / "gid.txt", gid)) {
        std::cerr << "Failed to write gid" << std::endl;
        return 12;
    }
    if (!trapdoor_timing_out.empty()) {
        std::ostringstream output;
        output << std::fixed << std::setprecision(3) << trapdoor_gen_ms;
        if (!WriteTextFile(trapdoor_timing_out, output.str())) {
            std::cerr << "Failed to write trapdoor timing" << std::endl;
            return 13;
        }
    }

    std::cout << "Query request prepared at " << request_dir << std::endl;
    std::cout << "Trapdoor generation ms: " << std::fixed << std::setprecision(3) << trapdoor_gen_ms << std::endl;
    return 0;
}
