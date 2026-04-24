#include <iostream>

#include "phase1_setup.h"
#include "phase2_keygen.h"
#include "phase4_search.h"
#include "system/Artifacts.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    const auto gid = cli.Require("--gid");
    const auto request_dir = std::filesystem::path(cli.Require("--request-dir"));
    const auto response_dir = std::filesystem::path(cli.Require("--response-dir"));

    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
        return 1;
    }

    UserCredentialRecord credential;
    if (!LoadUserCredentialRecord(gid, credential)) {
        std::cerr << "Failed to load credential for " << gid << std::endl;
        return 2;
    }
    UserSecretKey user_key;
    if (!LoadUserSecretKey(params, user_key, credential.user_key_path)) {
        std::cerr << "Failed to load user secret key for " << gid << std::endl;
        return 3;
    }

    SearchTrapdoor trapdoor;
    if (!LoadSearchTrapdoor(params, trapdoor, (request_dir / "shortlist_trapdoor.bin").string())) {
        std::cerr << "Failed to load shortlist trapdoor" << std::endl;
        return 4;
    }

    const auto bundle_root = response_dir / "bundles";
    if (!std::filesystem::exists(bundle_root)) {
        std::cerr << "No bundles directory in response" << std::endl;
        return 5;
    }

    bool any_success = false;
    for (const auto& entry : std::filesystem::directory_iterator(bundle_root)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".bin") {
            continue;
        }
        CiphertextBundle bundle;
        if (!LoadCiphertextBundle(params, bundle, entry.path().string())) {
            continue;
        }
        SearchResult result;
        if (!RetrieveAndDecrypt(params, user_key, bundle, trapdoor, result)) {
            continue;
        }
        any_success = true;
        std::cout << "Bundle: " << bundle.bundle_label << '\n';
        std::cout << "Matched keywords:";
        for (const auto& keyword : result.matched_keywords) {
            std::cout << ' ' << keyword;
        }
        std::cout << '\n';
        std::cout << "Plaintext:\n" << result.plaintext << std::endl;
    }

    return any_success ? 0 : 6;
}
