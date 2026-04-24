#pragma once

#include <filesystem>

namespace abse_zkp {

std::filesystem::path WorkspaceRoot();
std::filesystem::path RuntimeRoot();
std::filesystem::path StateRoot();
std::filesystem::path AbseArtifactRoot();
std::filesystem::path UserArtifactRoot();
std::filesystem::path CiphertextArtifactRoot();
std::filesystem::path CloudArtifactRoot();
std::filesystem::path SearchArtifactRoot();
std::filesystem::path UpdateTokenRoot();
std::filesystem::path ExperimentArtifactRoot();
void EnsureRuntimeDirectories();

}  // namespace abse_zkp
