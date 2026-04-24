#include "CloudServer.h"
#include "BlockchainClient.h"
#include <stdexcept>
#include <filesystem>
#include <sstream>
#include <cstdio>
#include <chrono>
#include <fstream>
#include <oqs/oqs.h>

namespace {
constexpr std::int64_t kAllowedClockSkewSeconds = 300;

std::filesystem::path find_workspace_root() {
    std::filesystem::path current = std::filesystem::current_path();
    for (int i = 0; i < 4; ++i) {
        if (std::filesystem::exists(current / "zk" / "scripts")) {
            return current;
        }
        if (!current.has_parent_path()) {
            break;
        }
        current = current.parent_path();
    }
    return std::filesystem::current_path();
}

std::string quote_argument(const std::string& value) {
    return "\"" + value + "\"";
}

std::string quote_path(const std::filesystem::path& path) {
    return quote_argument(path.string());
}

std::string run_command_capture(const std::string& command) {
    std::string output;
    FILE* pipe = _popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return output;
    }

    char buffer[256];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    _pclose(pipe);
    return output;
}

std::string make_nonce_key(int epoch, int nonce) {
    return std::to_string(epoch) + "|" + std::to_string(nonce);
}

std::int64_t current_unix_timestamp() {
    using clock = std::chrono::system_clock;
    return static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(clock::now().time_since_epoch()).count()
    );
}

double elapsed_ms(const std::chrono::high_resolution_clock::time_point& start,
                  const std::chrono::high_resolution_clock::time_point& end) {
    return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - start).count();
}

} // namespace

CloudServer::CloudServer(const IdentityAuthority& authority) {
    // Initialize by syncing with the Genesis block
    sync_with_blockchain();
    re_encryption_key_buffer = "EMPTY";
    ia_public_key = authority.get_public_key();
    ia_signature_algorithm = authority.get_signature_algorithm();
    const std::filesystem::path workspace_root = find_workspace_root();
    node_verify_script = (workspace_root / "zk" / "scripts" / "verify_membership.mjs").string();
    used_nonces_path = workspace_root / "zk" / "build" / "runtime_cpp" / "used_nonces.txt";
    load_used_nonces();
    prune_used_nonces_for_current_epoch();
    std::cout << "[CS] Cloud Server Initialized. Synced to Epoch " << internal_tag.epoch << std::endl;
}

void CloudServer::upload_data(Ciphertext C) {
    database.push_back(C);
    std::cout << "[CS] File " << C.file_id << " securely archived." << std::endl;
}

void CloudServer::sync_with_blockchain() {
    Blockchain.sync_from_chain();
    internal_tag = Blockchain.current_state;
    prune_used_nonces_for_current_epoch();
}

void CloudServer::load_used_nonces() {
    used_nonces.clear();
    std::filesystem::create_directories(used_nonces_path.parent_path());

    std::ifstream input(used_nonces_path);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty()) {
            used_nonces.insert(line);
        }
    }
}

void CloudServer::persist_used_nonces() const {
    std::filesystem::create_directories(used_nonces_path.parent_path());
    std::ofstream output(used_nonces_path, std::ios::trunc);
    for (const auto& key : used_nonces) {
        output << key << "\n";
    }
}

void CloudServer::prune_used_nonces_for_current_epoch() {
    std::unordered_set<std::string> filtered;
    const std::string epoch_prefix = std::to_string(internal_tag.epoch) + "|";

    for (const auto& key : used_nonces) {
        if (key.rfind(epoch_prefix, 0) == 0) {
            filtered.insert(key);
        }
    }

    if (filtered.size() != used_nonces.size()) {
        used_nonces = std::move(filtered);
        persist_used_nonces();
    }
}

void CloudServer::receive_re_encryption_key(std::string RK) {
    re_encryption_key_buffer = RK;
    sync_with_blockchain(); // CS advances its own epoch
    std::cout << "[CS] Received RK from TA. Buffered securely. Internal state updated to Epoch " 
              << internal_tag.epoch << ". (Files remain dormant!)" << std::endl;
}

void CloudServer::ReEncrypt(Ciphertext& C) {
    std::cout << "     >> [LATTICE MATH] Applying RK: " << re_encryption_key_buffer << " to File " << C.file_id << "..." << std::endl;
    
    // Simulate the lattice transformation shifting the ciphertext to the new epoch
    C.encrypted_data = C.encrypted_data + "_upgraded_to_epoch_" + std::to_string(internal_tag.epoch);
    C.file_tag = internal_tag; 
    C.is_reencrypted = true;
    
    std::cout << "     >> [SUCCESS] File " << C.file_id << " transformed to Epoch " << C.file_tag.epoch << "!" << std::endl;
}

bool CloudServer::verify_auth_token(const AuthToken& token) {
    sync_with_blockchain();

    OQS_SIG* verifier = OQS_SIG_new(ia_signature_algorithm.c_str());
    if (verifier == nullptr) {
        std::cout << "[CS] Authentication failed: verifier unavailable." << std::endl;
        return false;
    }

    const std::string payload = token.user_gid + "|" + token.zk_id + "|" +
                                std::to_string(token.leaf_index) + "|" +
                                std::to_string(token.issued_tag.epoch) + "|" +
                                token.issued_tag.revocation_root + "|" +
                                token.registration_root + "|" +
                                std::to_string(token.nonce) + "|" +
                                std::to_string(token.issued_at_unix);

    const OQS_STATUS signature_ok = OQS_SIG_verify(
        verifier,
        reinterpret_cast<const uint8_t*>(payload.data()),
        payload.size(),
        token.signature.data(),
        token.signature.size(),
        ia_public_key.data());

    OQS_SIG_free(verifier);

    if (signature_ok != OQS_SUCCESS) {
        std::cout << "[CS] Authentication failed: token signature is invalid." << std::endl;
        return false;
    }

    if (token.issued_tag.epoch != internal_tag.epoch ||
        token.issued_tag.revocation_root != internal_tag.revocation_root) {
        std::cout << "[CS] Authentication failed: token is stale after a state update." << std::endl;
        return false;
    }

    if (token.public_file_path.empty() || token.proof_file_path.empty()) {
        std::cout << "[CS] Authentication failed: token is missing its real ZKP bundle." << std::endl;
        return false;
    }

    const std::string nonce_key = make_nonce_key(token.issued_tag.epoch, token.nonce);
    if (used_nonces.find(nonce_key) != used_nonces.end()) {
        std::cout << "[CS] Authentication failed: nonce was already used." << std::endl;
        return false;
    }

    if (std::llabs(current_unix_timestamp() - token.issued_at_unix) > kAllowedClockSkewSeconds) {
        std::cout << "[CS] Authentication failed: token timestamp is outside the allowed window." << std::endl;
        return false;
    }

    const std::string verify_command = "node " + quote_path(node_verify_script) + " " +
                                       quote_argument(token.public_file_path) + " " +
                                       quote_argument(token.proof_file_path) + " " +
                                       quote_argument(BlockchainClient::hex_bytes32_to_decimal(token.registration_root)) + " " +
                                       quote_argument(BlockchainClient::hex_bytes32_to_decimal(token.issued_tag.revocation_root)) + " " +
                                       quote_argument(std::to_string(token.nonce)) + " " +
                                       quote_argument(std::to_string(token.issued_at_unix)) +
                                       " 2>&1";
    const auto verify_start = std::chrono::high_resolution_clock::now();
    const std::string verify_output = run_command_capture(verify_command);
    const auto verify_end = std::chrono::high_resolution_clock::now();
    const double verify_ms = elapsed_ms(verify_start, verify_end);
    last_verify_time_ms = verify_ms;
    if (verify_output.find("OK!") == std::string::npos) {
        std::cout << "[CS] Authentication failed: real ZKP verification did not succeed." << std::endl;
        std::cout << "     verify time: " << std::fixed << std::setprecision(verify_ms >= 1000.0 ? 2 : 3)
                  << (verify_ms >= 1000.0 ? verify_ms / 1000.0 : verify_ms)
                  << (verify_ms >= 1000.0 ? " s" : " ms") << std::endl;
        if (!verify_output.empty()) {
            std::cout << "     verifier output: " << verify_output;
        }
        return false;
    }

    std::cout << "[CS] Authentication successful for " << token.user_gid
              << " at Epoch " << internal_tag.epoch << " with a verified real ZKP" << std::endl;
    std::cout << "     verify time: " << std::fixed << std::setprecision(verify_ms >= 1000.0 ? 2 : 3)
              << (verify_ms >= 1000.0 ? verify_ms / 1000.0 : verify_ms)
              << (verify_ms >= 1000.0 ? " s" : " ms") << std::endl;
    used_nonces.insert(nonce_key);
    persist_used_nonces();
    return true;
}

double CloudServer::get_last_verify_time_ms() const {
    return last_verify_time_ms;
}

Ciphertext CloudServer::search_and_retrieve(const AuthToken& token, int requested_file_id) {
    std::cout << "\n[CS] Incoming Search Request for File " << requested_file_id << "..." << std::endl;

    if (!verify_auth_token(token)) {
        throw std::runtime_error("Authentication Failed");
    }
    
    // 1. Find the file in our mock database (Simulating the SOL candidate pruning)
    Ciphertext* target_file = nullptr;
    for (auto& file : database) {
        if (file.file_id == requested_file_id) {
            target_file = &file;
            break;
        }
    }

    if (target_file == nullptr) {
        std::cout << "[CS] File not found." << std::endl;
        throw std::runtime_error("File Not Found");
    }

    // 2. The Lazy Version Discrepancy Check (Phase 4, Step 4)
    std::cout << "[CS] Checking File Freshness..." << std::endl;
    std::cout << "     Server Epoch: " << internal_tag.epoch << " | File Epoch: " << target_file->file_tag.epoch << std::endl;

    if (target_file->file_tag.epoch != internal_tag.epoch) {
        std::cout << "[CS] VERSION MISMATCH DETECTED! Triggering Just-In-Time Re-encryption..." << std::endl;
        ReEncrypt(*target_file);
    } else {
        std::cout << "[CS] File is fresh. No re-encryption needed." << std::endl;
    }

    std::cout << "[CS] Delivering Ciphertext to MDU..." << std::endl;
    return *target_file;
}
