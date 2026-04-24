#pragma once

#include <filesystem>

#include "pq_src/IdentityAuthority.h"

namespace abse_zkp {

bool SaveAuthToken(const AuthToken& token, const std::filesystem::path& path);
bool LoadAuthToken(const std::filesystem::path& path, AuthToken& token);

}  // namespace abse_zkp
