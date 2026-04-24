#include "system/RuntimePaths.h"

namespace abse_zkp {

std::filesystem::path WorkspaceRoot() {
#ifdef ABSE_ZKP_SOURCE_DIR
    return std::filesystem::path(ABSE_ZKP_SOURCE_DIR);
#else
    return std::filesystem::current_path();
#endif
}

std::filesystem::path RuntimeRoot() { return WorkspaceRoot() / "runtime"; }
std::filesystem::path StateRoot() { return RuntimeRoot() / "state"; }
std::filesystem::path AbseArtifactRoot() { return RuntimeRoot() / "abse"; }
std::filesystem::path UserArtifactRoot() { return RuntimeRoot() / "users"; }
std::filesystem::path CiphertextArtifactRoot() { return RuntimeRoot() / "ciphertexts"; }
std::filesystem::path CloudArtifactRoot() { return RuntimeRoot() / "cloud"; }
std::filesystem::path SearchArtifactRoot() { return RuntimeRoot() / "search"; }
std::filesystem::path UpdateTokenRoot() { return StateRoot() / "update_tokens"; }
std::filesystem::path ExperimentArtifactRoot() { return RuntimeRoot() / "experiments"; }

void EnsureRuntimeDirectories() {
    std::filesystem::create_directories(RuntimeRoot());
    std::filesystem::create_directories(StateRoot());
    std::filesystem::create_directories(AbseArtifactRoot());
    std::filesystem::create_directories(UserArtifactRoot());
    std::filesystem::create_directories(CiphertextArtifactRoot());
    std::filesystem::create_directories(CloudArtifactRoot());
    std::filesystem::create_directories(SearchArtifactRoot());
    std::filesystem::create_directories(UpdateTokenRoot());
    std::filesystem::create_directories(ExperimentArtifactRoot());
}

}  // namespace abse_zkp
