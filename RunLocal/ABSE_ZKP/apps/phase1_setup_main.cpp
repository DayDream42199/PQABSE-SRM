#include <iostream>

#include "phase1_setup.h"
#include "system/Cli.h"
#include "system/RuntimePaths.h"

int main(int argc, char** argv) {
    using namespace abse_zkp;
    EnsureRuntimeDirectories();
    CliArgs cli(argc, argv);

    SystemParams params{};
    PK pk;
    MSK msk;

    const uint32_t ring_dim = static_cast<uint32_t>(std::stoul(cli.Get("--ring-dim", "256")));
    const uint64_t modulus = static_cast<uint64_t>(std::stoull(cli.Get("--modulus", "12289")));
    const double stddev = std::stod(cli.Get("--stddev", "3.2"));
    const int64_t gadget_base = static_cast<int64_t>(std::stoll(cli.Get("--gadget-base", "2")));
    const bool balanced = cli.HasFlag("--balanced");

    InitSystemParams(params, ring_dim, modulus, stddev, gadget_base, balanced);
    Setup(params, pk, msk);
    if (!SavePhase1Artifacts(params, pk, msk, AbseArtifactRoot().string())) {
        std::cerr << "Failed to save Phase 1 artifacts" << std::endl;
        return 1;
    }
    std::cout << "Phase 1 setup complete. Artifacts written to: " << AbseArtifactRoot() << std::endl;
    return 0;
}
