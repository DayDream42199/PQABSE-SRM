#include "TrustedAuthority.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>

extern "C" {
#include "poseidon.h"
}

namespace {

constexpr int kQ = 12289;
constexpr std::size_t kDefaultTrapdoorRows = 14;
constexpr std::size_t kDefaultTrapdoorCols = 256;

int normalize_mod_q(int value) {
    int reduced = value % kQ;
    if (reduced < 0) {
        reduced += kQ;
    }
    return reduced;
}

std::filesystem::path find_workspace_root() {
#ifdef ABSE_ZKP_SOURCE_DIR
    return std::filesystem::path(ABSE_ZKP_SOURCE_DIR);
#else
    return std::filesystem::current_path();
#endif
}

std::uint64_t read_u64_le(const std::vector<unsigned char>& bytes, std::size_t offset) {
    std::uint64_t value = 0;
    const std::size_t limit = std::min<std::size_t>(8, bytes.size() - offset);
    for (std::size_t i = 0; i < limit; ++i) {
        value |= static_cast<std::uint64_t>(bytes[offset + i]) << (8 * i);
    }
    return value;
}

std::vector<std::vector<int>> derive_trapdoor_matrix_from_binary(const std::vector<unsigned char>& bytes) {
    std::size_t rows = kDefaultTrapdoorRows;
    std::size_t cols = kDefaultTrapdoorCols;
    std::size_t header_size = 0;

    if (bytes.size() >= 32) {
        const std::uint64_t maybe_outer = read_u64_le(bytes, 0);
        const std::uint64_t maybe_cols = read_u64_le(bytes, 8);
        const std::uint64_t maybe_total = read_u64_le(bytes, 16);
        if (maybe_outer == 1 && maybe_cols > 0 && maybe_total > 0 && maybe_total % maybe_cols == 0) {
            cols = static_cast<std::size_t>(maybe_cols);
            rows = static_cast<std::size_t>(maybe_total / maybe_cols);
            header_size = 32;
        }
    }

    const std::size_t payload_offset = std::min(header_size, bytes.size());
    const std::size_t payload_size = bytes.size() - payload_offset;
    if (payload_size == 0) {
        return {};
    }

    std::vector<std::vector<int>> matrix(rows, std::vector<int>(cols, 0));
    const std::size_t total_entries = rows * cols;
    for (std::size_t index = 0; index < total_entries; ++index) {
        const std::size_t a = payload_offset + (index % payload_size);
        const std::size_t b = payload_offset + ((index + total_entries) % payload_size);
        const int symbol = static_cast<int>((static_cast<unsigned int>(bytes[a]) +
                                             (static_cast<unsigned int>(bytes[b]) << 8)) % 3U);
        int value = 0;
        if (symbol == 1) value = 1;
        else if (symbol == 2) value = -1;
        matrix[index / cols][index % cols] = normalize_mod_q(value);
    }
    return matrix;
}

std::string join_mod_q_vector(const std::vector<int>& values) {
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) out << ",";
        out << normalize_mod_q(values[i]);
    }
    return out.str();
}

void clear_felt(felt_t value) {
    std::memset(value, 0, sizeof(felt_t));
}

void string_to_felt(const std::string& input, felt_t out) {
    clear_felt(out);
    const size_t mapped_value = std::hash<std::string>{}(input);
    std::memcpy(&out[0], &mapped_value, sizeof(mapped_value));
}

std::string felt_to_hex_string(const felt_t value) {
    char hex_output[65];
    const unsigned char* raw_bytes = reinterpret_cast<const unsigned char*>(value);
    for (int i = 0; i < 32; ++i) {
        std::sprintf(&hex_output[i * 2], "%02x", raw_bytes[i]);
    }
    return std::string(hex_output, 64);
}

} // namespace

TrustedAuthority::TrustedAuthority(const std::filesystem::path& artifact_dir)
    : artifact_directory(find_workspace_root() / artifact_dir) {
    if (!load_master_secret_trapdoor("phase1_trapdoor.bin") &&
        !load_master_secret_trapdoor("trapdoor.bin") &&
        !load_master_secret_trapdoor("trapdoor.txt")) {
        throw std::runtime_error("Failed to load ABSE trapdoor artifacts for the Trusted Authority");
    }
}

bool TrustedAuthority::load_master_secret_trapdoor(const std::string& trapdoor_path) {
    const std::vector<std::filesystem::path> candidates = {
        artifact_directory / trapdoor_path,
        find_workspace_root() / trapdoor_path,
        std::filesystem::current_path() / trapdoor_path
    };
    for (const auto& candidate : candidates) {
        std::ifstream input(candidate, std::ios::binary);
        if (!input.is_open()) {
            continue;
        }
        const std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        master_secret_trapdoor = derive_trapdoor_matrix_from_binary(bytes);
        return !master_secret_trapdoor.empty();
    }
    return false;
}

std::string TrustedAuthority::real_poseidon_hash(const std::string& input) const {
    felt_t state[3];
    std::memset(state, 0, sizeof(state));
    string_to_felt(input, state[0]);
    permutation_3(state);
    return felt_to_hex_string(state[1]);
}

bool TrustedAuthority::generate_re_encryption_material(const UserRecord& revoked_user,
                                                       int new_epoch,
                                                       ReEncryptionMaterial& material) const {
    if (revoked_user.user_gid.empty() || master_secret_trapdoor.empty()) {
        return false;
    }
    const int old_epoch = new_epoch - 1;
    const std::string seed = real_poseidon_hash(revoked_user.user_gid + "|" + revoked_user.zk_id + "|" +
                                                std::to_string(old_epoch) + "|" + std::to_string(new_epoch));
    std::vector<int> challenge;
    challenge.reserve(seed.size());
    for (char ch : seed) {
        challenge.push_back(normalize_mod_q(static_cast<int>(ch)));
    }
    std::vector<int> projection;
    projection.reserve(master_secret_trapdoor.size());
    for (const auto& row : master_secret_trapdoor) {
        long long acc = 0;
        for (size_t i = 0; i < row.size(); ++i) {
            acc += static_cast<long long>(row[i]) * challenge[i % challenge.size()];
        }
        projection.push_back(normalize_mod_q(static_cast<int>(acc % kQ)));
    }
    const std::string projection_encoding = join_mod_q_vector(projection);
    material.old_epoch = old_epoch;
    material.new_epoch = new_epoch;
    material.re_encryption_key = real_poseidon_hash("RK|" + projection_encoding + "|" + revoked_user.user_gid);
    material.update_token = real_poseidon_hash("UT|" + projection_encoding + "|" + std::to_string(revoked_user.leaf_index));
    return true;
}

bool TrustedAuthority::generate_update_token_for_user(const UserRecord& user,
                                                      int new_epoch,
                                                      std::string& update_token) const {
    return generate_update_token_for_user(user, new_epoch, std::string(), update_token);
}

bool TrustedAuthority::generate_update_token_for_user(const UserRecord& user,
                                                      int new_epoch,
                                                      const std::string& update_token_seed,
                                                      std::string& update_token) const {
    if (user.user_gid.empty()) {
        return false;
    }
    const int old_epoch = new_epoch - 1;
    const std::string seed = update_token_seed.empty()
        ? real_poseidon_hash("UTSEED|" + std::to_string(old_epoch) + "|" + std::to_string(new_epoch))
        : update_token_seed;
    update_token = real_poseidon_hash("UT|" + seed + "|" + user.user_gid + "|" + user.zk_id + "|" +
                                      std::to_string(user.leaf_index) + "|" +
                                      std::to_string(old_epoch) + "|" + std::to_string(new_epoch));
    return true;
}

bool TrustedAuthority::derive_bitmap_epoch_key(int epoch, std::string& epoch_bitmap_key) const {
    if (master_secret_trapdoor.empty()) {
        return false;
    }

    std::vector<int> fingerprint;
    fingerprint.reserve(master_secret_trapdoor.size());
    for (const auto& row : master_secret_trapdoor) {
        int acc = 0;
        for (size_t i = 0; i < row.size(); ++i) {
            acc = normalize_mod_q(acc + row[i] * static_cast<int>((i % 7) + 1));
        }
        fingerprint.push_back(acc);
    }

    epoch_bitmap_key = real_poseidon_hash("BK|" + join_mod_q_vector(fingerprint) + "|" + std::to_string(epoch));
    return true;
}
