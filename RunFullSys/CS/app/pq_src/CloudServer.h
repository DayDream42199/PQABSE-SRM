#pragma once
#include <string>
#include <unordered_set>
#include <vector>
#include <iostream>
#include <filesystem>
#include "Blockchain.h"
#include "IdentityAuthority.h"

// ========================================================
// 1. DATA STRUCTURE (Moved from main)
// ========================================================
struct Ciphertext {
    int file_id;
    std::string encrypted_data; 
    VersionTag file_tag;        // The version attached by MDO during upload
    bool is_reencrypted;        // Flag to prove the lazy re-encryption fired
};

// ========================================================
// 2. CLOUD SERVER (CS)
// ========================================================
class CloudServer {
private:
    VersionTag internal_tag;                 // V_tag,CS (The server's synced state)
    std::string re_encryption_key_buffer;    // Stores the RK from the TA
    std::vector<Ciphertext> database;        // The outsourced encrypted files
    std::vector<uint8_t> ia_public_key;      // Public verification key published by IA
    std::string ia_signature_algorithm;      // Signature scheme used by IA
    std::string node_verify_script;
    std::filesystem::path used_nonces_path;
    std::unordered_set<std::string> used_nonces;
    double last_verify_time_ms = 0.0;

    // The internal lattice transformation function
    void ReEncrypt(Ciphertext& C);
    bool verify_auth_token(const AuthToken& token);
    void load_used_nonces();
    void persist_used_nonces() const;
    void prune_used_nonces_for_current_epoch();

public:
    explicit CloudServer(const IdentityAuthority& authority);

    // Phase 3: Receive uploaded data
    void upload_data(Ciphertext C);

    // Phase 5: Receive the RK from TA after a revocation
    void receive_re_encryption_key(std::string RK);

    // Phase 4: Sync with Blockchain
    void sync_with_blockchain();

    // Phase 4: The Just-In-Time Search
    Ciphertext search_and_retrieve(const AuthToken& token, int requested_file_id);
    double get_last_verify_time_ms() const;
};
