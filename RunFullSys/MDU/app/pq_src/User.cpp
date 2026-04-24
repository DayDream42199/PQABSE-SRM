#include "User.h"
#include "BlockchainClient.h"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <cstdlib>
#include <random>
#include <chrono>
#include <iomanip>

namespace {
constexpr int kQ = 12289;

std::filesystem::path find_workspace_root() {
#ifdef ABSE_ZKP_SOURCE_DIR
    return std::filesystem::path(ABSE_ZKP_SOURCE_DIR);
#else
    return std::filesystem::current_path();
#endif
}

std::string escape_json(const std::string& input) {
    std::ostringstream out;
    for (char ch : input) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << ch; break;
        }
    }
    return out.str();
}

std::string quote_path(const std::filesystem::path& path) {
    return "\"" + path.string() + "\"";
}

bool run_command(const std::string& command) {
    return std::system(command.c_str()) == 0;
}

double elapsed_ms(const std::chrono::high_resolution_clock::time_point& start,
                  const std::chrono::high_resolution_clock::time_point& end) {
    return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - start).count();
}

std::string format_duration(double duration_ms) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(duration_ms >= 1000.0 ? 2 : 3);
    if (duration_ms >= 1000.0) {
        out << (duration_ms / 1000.0) << " s";
    } else {
        out << duration_ms << " ms";
    }
    return out.str();
}

int generate_identity_secret_mod_q() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, kQ - 1);
    return dist(rng);
}

std::map<std::string, std::string> parse_meta_file(const std::filesystem::path& meta_path) {
    std::ifstream input(meta_path);
    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        const size_t split = line.find('=');
        if (split == std::string::npos) {
            continue;
        }
        values[line.substr(0, split)] = line.substr(split + 1);
    }
    return values;
}

bool generate_user_zkp_bundle(const std::string& gid,
                              int identity_secret,
                              AuthToken& token,
                              std::string& proof_file_path,
                              std::string& public_file_path) {
    const std::filesystem::path workspace_root = find_workspace_root();
    const std::filesystem::path runtime_root = workspace_root / "zk" / "build" / "runtime_cpp" / "tokens";
    std::filesystem::create_directories(runtime_root);

    if (token.prover_state_path.empty()) {
        return false;
    }

    const std::filesystem::path out_dir = runtime_root / (gid + "_epoch_" + std::to_string(token.issued_tag.epoch));
    std::filesystem::create_directories(out_dir);

    const std::filesystem::path meta_path = out_dir / "meta.txt";
    const std::filesystem::path auth_state_path = out_dir / "auth_state.json";

    std::ifstream state_input(token.prover_state_path);
    if (!state_input.is_open()) {
        return false;
    }
    std::string state_content((std::istreambuf_iterator<char>(state_input)), std::istreambuf_iterator<char>());
    state_input.close();

    const std::string users_marker = "\"users\": [";
    const std::size_t users_position = state_content.find(users_marker);
    if (users_position == std::string::npos) {
        return false;
    }

    state_content.insert(users_position,
                         "  \"target_gid\": \"" + escape_json(gid) + "\",\n"
                         "  \"target_secret\": \"" + std::to_string(identity_secret) + "\",\n");
    std::ofstream auth_state_output(auth_state_path);
    auth_state_output << state_content;
    auth_state_output.close();

    const std::filesystem::path script_path = workspace_root / "zk" / "scripts" / "generate_cpp_auth_bundle.mjs";
    const std::string command = "node " + quote_path(script_path) + " " +
                                quote_path(auth_state_path) + " " +
                                quote_path(out_dir) + " " +
                                quote_path(meta_path) + " " +
                                std::to_string(token.nonce) + " " +
                                std::to_string(token.issued_at_unix);
    const auto prove_start = std::chrono::high_resolution_clock::now();
    if (!run_command(command)) {
        return false;
    }
    const auto prove_end = std::chrono::high_resolution_clock::now();
    token.prove_time_ms = elapsed_ms(prove_start, prove_end);

    const auto meta_values = parse_meta_file(meta_path);
    const auto proof_it = meta_values.find("proof_file");
    const auto public_it = meta_values.find("public_file");
    const auto reg_it = meta_values.find("registration_root");
    const auto rev_it = meta_values.find("revocation_root");
    if (proof_it == meta_values.end() || public_it == meta_values.end() ||
        reg_it == meta_values.end() || rev_it == meta_values.end()) {
        return false;
    }

    if (BlockchainClient::decimal_to_hex_bytes32(reg_it->second) != token.registration_root ||
        BlockchainClient::decimal_to_hex_bytes32(rev_it->second) != token.issued_tag.revocation_root) {
        return false;
    }

    proof_file_path = proof_it->second;
    public_file_path = public_it->second;
    std::cout << "       prove time: " << format_duration(token.prove_time_ms) << std::endl;
    return true;
}

} // namespace

User::User(std::string gid_value, int known_identity_secret, bool has_secret)
    : gid(std::move(gid_value)),
      identity_secret(known_identity_secret),
      has_identity_secret(has_secret) {}

const std::string& User::get_gid() const {
    return gid;
}

const AuthToken& User::get_auth_token() const {
    return auth_token;
}

int User::get_identity_secret() const {
    return identity_secret;
}

void User::set_identity_secret(int new_identity_secret) {
    identity_secret = new_identity_secret;
    has_identity_secret = true;
}

bool User::register_with_authority(IdentityAuthority& authority) {
    if (!has_identity_secret) {
        identity_secret = generate_identity_secret_mod_q();
        has_identity_secret = true;
    }
    authority.register_user(gid, identity_secret);
    return true;
}

bool User::request_authentication(IdentityAuthority& authority) {
    return request_zkp_authentication(authority);
}

bool User::request_zkp_authentication(IdentityAuthority& authority) {
    if (!authority.authenticate_user(gid, auth_token)) {
        return false;
    }
    if (!has_identity_secret) {
        return false;
    }

    std::string proof_path;
    std::string public_path;
    if (!generate_user_zkp_bundle(gid, identity_secret, auth_token, proof_path, public_path)) {
        auth_token.proof_file_path.clear();
        auth_token.public_file_path.clear();
        return false;
    }

    auth_token.proof_file_path = proof_path;
    auth_token.public_file_path = public_path;
    return true;
}

bool User::request_registration_auth_path(const IdentityAuthority& authority, std::vector<MerkleProofNode>& auth_path) const {
    return authority.get_registration_auth_path(gid, auth_path);
}
