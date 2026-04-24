#include "IdentityAuthority.h"
#include "BlockchainClient.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <oqs/oqs.h>

extern "C" {
#include "poseidon.h"
}

namespace {

constexpr int kQ = 12289;
constexpr int kTreeDepth = 8;

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

std::string poseidon_hash_string(const std::string& input) {
    felt_t state[3];
    std::memset(state, 0, sizeof(state));
    string_to_felt(input, state[0]);
    permutation_3(state);
    return felt_to_hex_string(state[1]);
}

std::string poseidon_compress(const std::string& left, const std::string& right) {
    felt_t state[3];
    std::memset(state, 0, sizeof(state));
    string_to_felt(left, state[0]);
    string_to_felt(right, state[1]);
    permutation_3(state);
    return felt_to_hex_string(state[1]);
}

int normalize_mod_q(int value) {
    int reduced = value % kQ;
    if (reduced < 0) {
        reduced += kQ;
    }
    return reduced;
}

int generate_nonce_mod_q() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, kQ - 1);
    return dist(rng);
}

std::int64_t current_unix_timestamp() {
    using clock = std::chrono::system_clock;
    return static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(clock::now().time_since_epoch()).count()
    );
}

std::filesystem::path find_workspace_root() {
#ifdef ABSE_ZKP_SOURCE_DIR
    return std::filesystem::path(ABSE_ZKP_SOURCE_DIR);
#else
    std::filesystem::path current = std::filesystem::current_path();
    for (int i = 0; i < 8; ++i) {
        if (std::filesystem::exists(current / "zk" / "scripts") &&
            std::filesystem::exists(current / "abse_src")) {
            return current;
        }
        if (!current.has_parent_path()) {
            break;
        }
        current = current.parent_path();
    }
    return std::filesystem::current_path();
#endif
}

std::string quote_argument(const std::filesystem::path& path) {
    return "\"" + path.string() + "\"";
}

std::string quote_string(const std::string& value) {
    return "\"" + value + "\"";
}

bool run_command(const std::string& command) {
    return std::system(command.c_str()) == 0;
}

std::string run_command_capture(const std::string& command) {
    std::string output;
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return output;
    }
    char buffer[256];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }
    return output;
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

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (auto byte : bytes) {
        out << std::setw(2) << static_cast<int>(byte);
    }
    return out.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.size() % 2 != 0) {
        return bytes;
    }
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

std::map<std::string, std::string> load_key_values(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        values[line.substr(0, pos)] = line.substr(pos + 1);
    }
    return values;
}

std::string compute_registration_leaf_with_js(const std::filesystem::path& workspace_root,
                                              const std::string& gid,
                                              int identity_secret) {
    const std::filesystem::path script_path = workspace_root / "zk" / "scripts" / "compute_registration_leaf.mjs";
    const std::string command = "node " + quote_argument(script_path) + " " +
                                quote_string(gid) + " " +
                                quote_string(std::to_string(normalize_mod_q(identity_secret)));
    return run_command_capture(command);
}

std::string compute_zero_leaf_with_js(const std::filesystem::path& workspace_root) {
    static std::string cached_zero_leaf;
    if (!cached_zero_leaf.empty()) {
        return cached_zero_leaf;
    }

    const std::filesystem::path script_path = workspace_root / "zk" / "scripts" / "compute_zero_leaf.mjs";
    cached_zero_leaf = run_command_capture("node " + quote_argument(script_path));
    return cached_zero_leaf;
}

bool write_prover_state_snapshot(const std::filesystem::path& state_path,
                                 const std::unordered_map<std::string, UserRecord>& users) {
    std::vector<UserRecord> ordered_users;
    ordered_users.reserve(users.size());
    for (const auto& entry : users) {
        ordered_users.push_back(entry.second);
    }

    std::sort(ordered_users.begin(), ordered_users.end(), [](const UserRecord& left, const UserRecord& right) {
        return left.leaf_index < right.leaf_index;
    });

    std::ofstream state_output(state_path);
    if (!state_output.is_open()) {
        return false;
    }

    state_output << "{\n";
    state_output << "  \"depth\": " << kTreeDepth << ",\n";
    state_output << "  \"users\": [\n";
    for (size_t i = 0; i < ordered_users.size(); ++i) {
        const UserRecord& user = ordered_users[i];
        state_output << "    {\"gid\":\"" << escape_json(user.user_gid)
                     << "\",\"leaf\":\"" << user.registration_leaf
                     << "\",\"revoked\":" << (user.is_revoked ? "true" : "false") << "}";
        if (i + 1 < ordered_users.size()) {
            state_output << ",";
        }
        state_output << "\n";
    }
    state_output << "  ]\n";
    state_output << "}\n";
    return true;
}

} // namespace

MerkleTree::MerkleTree() {
    leaves.push_back(poseidon_hash_string("0"));
}

void MerkleTree::add_leaf(std::string hashed_id) {
    leaves.push_back(std::move(hashed_id));
}

void MerkleTree::update_leaf(int index, std::string new_value) {
    if (index >= 0 && index < static_cast<int>(leaves.size())) {
        leaves[static_cast<std::size_t>(index)] = std::move(new_value);
    }
}

std::string MerkleTree::get_root() const {
    if (leaves.empty()) {
        return poseidon_compress("empty_left", "empty_right");
    }

    std::vector<std::string> current_level = leaves;
    while (current_level.size() > 1) {
        std::vector<std::string> next_level;
        next_level.reserve((current_level.size() + 1) / 2);
        for (size_t i = 0; i < current_level.size(); i += 2) {
            const std::string& left = current_level[i];
            const std::string& right = (i + 1 < current_level.size()) ? current_level[i + 1] : current_level[i];
            next_level.push_back(poseidon_compress(left, right));
        }
        current_level = std::move(next_level);
    }
    return current_level.front();
}

int MerkleTree::get_leaf_count() const {
    return static_cast<int>(leaves.size());
}

std::vector<MerkleProofNode> MerkleTree::get_auth_path(int index) const {
    std::vector<MerkleProofNode> auth_path;
    if (index < 0 || index >= static_cast<int>(leaves.size())) {
        return auth_path;
    }

    std::vector<std::string> current_level = leaves;
    int current_index = index;

    while (current_level.size() > 1) {
        const int sibling_index = (current_index % 2 == 0) ? current_index + 1 : current_index - 1;
        const bool sibling_exists = sibling_index >= 0 && sibling_index < static_cast<int>(current_level.size());
        const int effective_sibling_index = sibling_exists ? sibling_index : current_index;

        auth_path.push_back({current_level[static_cast<std::size_t>(effective_sibling_index)], effective_sibling_index < current_index});

        std::vector<std::string> next_level;
        next_level.reserve((current_level.size() + 1) / 2);
        for (size_t i = 0; i < current_level.size(); i += 2) {
            const std::string& left = current_level[i];
            const std::string& right = (i + 1 < current_level.size()) ? current_level[i + 1] : current_level[i];
            next_level.push_back(poseidon_compress(left, right));
        }
        current_level = std::move(next_level);
        current_index /= 2;
    }

    return auth_path;
}

IdentityAuthority::IdentityAuthority(const std::filesystem::path& state_dir)
    : state_directory(find_workspace_root() / state_dir),
      signer_handle(nullptr) {
    std::filesystem::create_directories(state_directory);

    if (!load_state()) {
        OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (sig == nullptr) {
            throw std::runtime_error("ML-DSA-44 is not enabled in liboqs");
        }

        signer_handle = sig;
        public_key.resize(sig->length_public_key);
        secret_key.resize(sig->length_secret_key);

        if (OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
            OQS_SIG_free(sig);
            signer_handle = nullptr;
            throw std::runtime_error("Failed to generate IA signature keypair");
        }

        rebuild_trees_from_users();
        if (!refresh_zk_roots()) {
            throw std::runtime_error("Failed to initialize the ZKP registration/revocation roots");
        }
        if (!save_state()) {
            throw std::runtime_error("Failed to persist a newly initialized IA state");
        }
        std::cout << "[IA] Initialized new persistent authority state." << std::endl;
    } else {
        std::cout << "[IA] Loaded persistent authority state." << std::endl;
    }
}

IdentityAuthority::~IdentityAuthority() {
    if (signer_handle != nullptr) {
        OQS_SIG_free(static_cast<OQS_SIG*>(signer_handle));
        signer_handle = nullptr;
    }
}

std::string IdentityAuthority::real_poseidon_hash(std::string input) const {
    return poseidon_hash_string(input);
}

std::string IdentityAuthority::build_default_revocation_leaf(int leaf_index) const {
    (void)leaf_index;
    return compute_zero_leaf_with_js(find_workspace_root());
}

std::string IdentityAuthority::build_auth_payload(const UserRecord& user,
                                                  const VersionTag& tag,
                                                  const std::string& registration_root,
                                                  int nonce,
                                                  std::int64_t issued_at_unix) const {
    return user.user_gid + "|" + user.zk_id + "|" + std::to_string(user.leaf_index) + "|" +
           std::to_string(tag.epoch) + "|" + tag.revocation_root + "|" + registration_root + "|" +
           std::to_string(nonce) + "|" + std::to_string(issued_at_unix);
}

void IdentityAuthority::rebuild_trees_from_users() {
    RegistrationTree = MerkleTree();
    RevocationTree = MerkleTree();

    auto ordered_users = list_user_records();
    std::sort(ordered_users.begin(), ordered_users.end(), [](const UserRecord& left, const UserRecord& right) {
        return left.leaf_index < right.leaf_index;
    });

    int expected_index = 1;
    for (const auto& user : ordered_users) {
        while (expected_index < user.leaf_index) {
            RegistrationTree.add_leaf(poseidon_hash_string("gap|" + std::to_string(expected_index)));
            ++expected_index;
        }
        RegistrationTree.add_leaf(user.registration_leaf);
        expected_index = user.leaf_index + 1;
    }

    for (const auto& user : ordered_users) {
        while (RevocationTree.get_leaf_count() <= user.leaf_index) {
            const int next_index = RevocationTree.get_leaf_count();
            RevocationTree.add_leaf(build_default_revocation_leaf(next_index));
        }
        if (user.is_revoked) {
            RevocationTree.update_leaf(user.leaf_index, user.registration_leaf);
        }
    }
}

bool IdentityAuthority::refresh_zk_roots() {
    const std::filesystem::path workspace_root = find_workspace_root();
    const std::filesystem::path runtime_dir = workspace_root / "zk" / "build" / "runtime_cpp";
    std::filesystem::create_directories(runtime_dir);

    const std::filesystem::path state_path = runtime_dir / "roots_state.json";
    const std::filesystem::path meta_path = runtime_dir / "roots_meta.txt";

    if (!write_prover_state_snapshot(state_path, users)) {
        return false;
    }

    const std::filesystem::path script_path = workspace_root / "zk" / "scripts" / "compute_cpp_roots.mjs";
    const std::string command = "node " + quote_argument(script_path) + " " +
                                quote_argument(state_path) + " " + quote_argument(meta_path);
    if (!run_command(command)) {
        return false;
    }

    const auto meta_values = parse_meta_file(meta_path);
    auto reg_it = meta_values.find("registration_root");
    auto rev_it = meta_values.find("revocation_root");
    if (reg_it == meta_values.end() || rev_it == meta_values.end()) {
        return false;
    }

    zk_registration_root = BlockchainClient::decimal_to_hex_bytes32(reg_it->second);
    zk_revocation_root = BlockchainClient::decimal_to_hex_bytes32(rev_it->second);
    return true;
}

bool IdentityAuthority::load_state() {
    const auto path = state_directory / "identity_authority_state.txt";
    if (!std::filesystem::exists(path)) {
        return false;
    }

    const auto values = load_key_values(path);
    if (values.empty()) {
        return false;
    }

    public_key = hex_to_bytes(values.at("public_key_hex"));
    secret_key = hex_to_bytes(values.at("secret_key_hex"));

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig == nullptr) {
        throw std::runtime_error("ML-DSA-44 is not enabled in liboqs");
    }
    signer_handle = sig;

    users.clear();
    const int user_count = values.count("user_count") ? std::stoi(values.at("user_count")) : 0;
    for (int i = 0; i < user_count; ++i) {
        const std::string prefix = "user." + std::to_string(i) + ".";
        UserRecord user;
        user.user_gid = values.at(prefix + "gid");
        user.zk_id = values.at(prefix + "zk_id");
        user.registration_leaf = values.at(prefix + "registration_leaf");
        user.leaf_index = std::stoi(values.at(prefix + "leaf_index"));
        user.is_revoked = std::stoi(values.at(prefix + "is_revoked")) != 0;
        users[user.user_gid] = user;
    }

    rebuild_trees_from_users();
    return refresh_zk_roots();
}

bool IdentityAuthority::save_state() const {
    const auto path = state_directory / "identity_authority_state.txt";
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }

    output << "public_key_hex=" << bytes_to_hex(public_key) << '\n';
    output << "secret_key_hex=" << bytes_to_hex(secret_key) << '\n';

    auto ordered_users = list_user_records();
    std::sort(ordered_users.begin(), ordered_users.end(), [](const UserRecord& left, const UserRecord& right) {
        return left.leaf_index < right.leaf_index;
    });
    output << "user_count=" << ordered_users.size() << '\n';
    for (size_t i = 0; i < ordered_users.size(); ++i) {
        const auto& user = ordered_users[i];
        const std::string prefix = "user." + std::to_string(i) + ".";
        output << prefix << "gid=" << user.user_gid << '\n';
        output << prefix << "zk_id=" << user.zk_id << '\n';
        output << prefix << "registration_leaf=" << user.registration_leaf << '\n';
        output << prefix << "leaf_index=" << user.leaf_index << '\n';
        output << prefix << "is_revoked=" << (user.is_revoked ? 1 : 0) << '\n';
    }
    return static_cast<bool>(output);
}

UserRecord IdentityAuthority::register_user(std::string user_gid, int identity_secret) {
    identity_secret = normalize_mod_q(identity_secret);
    if (users.find(user_gid) != users.end()) {
        throw std::runtime_error("User already registered: " + user_gid);
    }

    const std::filesystem::path workspace_root = find_workspace_root();
    const std::string registration_leaf = compute_registration_leaf_with_js(workspace_root, user_gid, identity_secret);
    if (registration_leaf.empty()) {
        throw std::runtime_error("Failed to compute registration leaf for " + user_gid);
    }

    int next_leaf_index = 1;
    for (const auto& entry : users) {
        next_leaf_index = std::max(next_leaf_index, entry.second.leaf_index + 1);
    }

    UserRecord user{user_gid, registration_leaf, registration_leaf, next_leaf_index, false};
    users[user_gid] = user;
    rebuild_trees_from_users();
    if (!refresh_zk_roots() || !save_state()) {
        throw std::runtime_error("Failed to persist IA state after registering " + user_gid);
    }

    Blockchain.sync_from_chain();
    Blockchain.update_state(Blockchain.current_state.epoch,
                            zk_registration_root,
                            zk_revocation_root,
                            "registration of " + user_gid);
    return user;
}

bool IdentityAuthority::authenticate_user(const std::string& user_gid, AuthToken& token) {
    auto it = users.find(user_gid);
    if (it == users.end() || it->second.is_revoked) {
        return false;
    }

    Blockchain.sync_from_chain();
    UserRecord& user = it->second;
    token.user_gid = user.user_gid;
    token.zk_id = user.zk_id;
    token.nonce = generate_nonce_mod_q();
    token.issued_at_unix = current_unix_timestamp();
    token.leaf_index = user.leaf_index;
    token.issued_tag = Blockchain.current_state;
    token.registration_root = zk_registration_root;
    token.prover_state_path.clear();
    token.proof_file_path.clear();
    token.public_file_path.clear();

    const std::filesystem::path workspace_root = find_workspace_root();
    const std::filesystem::path runtime_root = workspace_root / "zk" / "build" / "runtime_cpp" / "tokens";
    std::filesystem::create_directories(runtime_root);
    const std::filesystem::path out_dir = runtime_root / (user_gid + "_epoch_" + std::to_string(token.issued_tag.epoch));
    std::filesystem::create_directories(out_dir);
    const std::filesystem::path prover_state_path = out_dir / "state.json";
    if (!write_prover_state_snapshot(prover_state_path, users)) {
        return false;
    }
    token.prover_state_path = prover_state_path.string();

    const std::string payload = build_auth_payload(user,
                                                   token.issued_tag,
                                                   token.registration_root,
                                                   token.nonce,
                                                   token.issued_at_unix);
    OQS_SIG* sig = static_cast<OQS_SIG*>(signer_handle);
    token.signature.resize(sig->length_signature);
    size_t signature_len = 0;
    if (OQS_SIG_sign(sig,
                     token.signature.data(),
                     &signature_len,
                     reinterpret_cast<const uint8_t*>(payload.data()),
                     payload.size(),
                     secret_key.data()) != OQS_SUCCESS) {
        token.signature.clear();
        return false;
    }
    token.signature.resize(signature_len);
    return true;
}

bool IdentityAuthority::get_registration_auth_path(const std::string& user_gid, std::vector<MerkleProofNode>& auth_path) const {
    auto it = users.find(user_gid);
    if (it == users.end()) {
        auth_path.clear();
        return false;
    }
    auth_path = RegistrationTree.get_auth_path(it->second.leaf_index);
    return true;
}

bool IdentityAuthority::revoke_user(const std::string& user_gid) {
    auto it = users.find(user_gid);
    if (it == users.end() || it->second.is_revoked) {
        return false;
    }

    it->second.is_revoked = true;
    rebuild_trees_from_users();
    if (!refresh_zk_roots() || !save_state()) {
        return false;
    }

    Blockchain.sync_from_chain();
    Blockchain.update_state(Blockchain.current_state.epoch + 1,
                            zk_registration_root,
                            zk_revocation_root,
                            "revocation of " + user_gid);
    return true;
}

bool IdentityAuthority::is_registered(const std::string& user_gid) const {
    return users.find(user_gid) != users.end();
}

bool IdentityAuthority::get_user_record(const std::string& user_gid, UserRecord& record) const {
    auto it = users.find(user_gid);
    if (it == users.end()) {
        return false;
    }
    record = it->second;
    return true;
}

std::vector<UserRecord> IdentityAuthority::list_user_records() const {
    std::vector<UserRecord> records;
    records.reserve(users.size());
    for (const auto& entry : users) {
        records.push_back(entry.second);
    }
    return records;
}

const std::filesystem::path& IdentityAuthority::get_state_directory() const {
    return state_directory;
}

const std::vector<uint8_t>& IdentityAuthority::get_public_key() const {
    return public_key;
}

size_t IdentityAuthority::get_public_key_length() const {
    return public_key.size();
}

const char* IdentityAuthority::get_signature_algorithm() const {
    return OQS_SIG_alg_ml_dsa_44;
}

std::string IdentityAuthority::get_registration_root() const {
    return zk_registration_root;
}

std::string IdentityAuthority::get_revocation_root() const {
    return zk_revocation_root;
}

std::string IdentityAuthority::serialize_auth_payload(const AuthToken& token) const {
    UserRecord user{token.user_gid, token.zk_id, "", token.leaf_index, false};
    return build_auth_payload(user,
                              token.issued_tag,
                              token.registration_root,
                              token.nonce,
                              token.issued_at_unix);
}
