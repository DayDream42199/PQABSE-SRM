#include <iostream>

#include "phase1_setup.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    CliArgs cli(argc, argv);
    const std::string label = cli.Get("--label", "verify-demo");
    SystemParams params{};
    PK pk;
    MSK msk;
    if (!LoadPhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        std::cerr << "Failed to load Phase 1 artifacts" << std::endl;
        return 1;
    }
    const auto syndrome = MakeDeterministicSyndrome(params, label);
    const auto preimage = SamplePreimage(params, pk, msk, syndrome);
    const bool ok = VerifyPreimage(pk, syndrome, preimage);
    std::cout << (ok ? "PASS" : "FAIL") << std::endl;
    return ok ? 0 : 2;
}
