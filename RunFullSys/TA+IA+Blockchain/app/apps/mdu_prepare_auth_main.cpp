#include <iostream>

#include "pq_src/IdentityAuthority.h"
#include "pq_src/TrustedAuthority.h"
#include "pq_src/User.h"
#include "system/Artifacts.h"
#include "system/AuthTokenIO.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const std::string gid = cli.Require("--gid");
    const std::string preferred_label = cli.Get("--label");
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

    if (!rekey_state.update_token_seed.empty() &&
        credential.local_epoch < Blockchain.current_state.epoch) {
        TrustedAuthority ta;
        std::string expected_token;
        std::string provided_token;
        if (!ta.generate_update_token_for_user(user_record,
                                               Blockchain.current_state.epoch,
                                               rekey_state.update_token_seed,
                                               expected_token)) {
            std::cerr << "Failed to derive expected update token" << std::endl;
            return 4;
        }
        if (!ReadTextFile(UpdateTokenPath(gid, Blockchain.current_state.epoch), provided_token) ||
            provided_token != expected_token) {
            std::cerr << "Missing or invalid update token for user " << gid << std::endl;
            return 5;
        }
    }

    User user(gid, credential.identity_secret, true);
    if (!user.request_zkp_authentication(ia, credential.attributes)) {
        std::cerr << "Failed to obtain proof-backed authentication token" << std::endl;
        return 6;
    }

    AuthToken token = user.get_auth_token();
    token.update_token = provided_token;

    std::filesystem::create_directories(request_dir);
    if (!SaveAuthToken(token, request_dir / "auth_token.txt")) {
        std::cerr << "Failed to write auth token" << std::endl;
        return 7;
    }
    if (!WriteTextFile(request_dir / "preferred_label.txt", preferred_label)) {
        std::cerr << "Failed to write preferred label" << std::endl;
        return 8;
    }
    if (!WriteTextFile(request_dir / "gid.txt", gid)) {
        std::cerr << "Failed to write gid" << std::endl;
        return 9;
    }

    std::cout << "Auth package prepared at " << request_dir << std::endl;
    return 0;
}
