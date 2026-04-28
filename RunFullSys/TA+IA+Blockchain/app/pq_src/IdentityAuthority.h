#pragma once
#include <string>
#include <cstdint>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include "Blockchain.h"

struct MerkleProofNode {
    std::string sibling_hash;
    bool sibling_is_left;
};

class MerkleTree {
private:
    std::vector<std::string> leaves;
public:
    MerkleTree();
    void add_leaf(std::string hashed_id);
    void update_leaf(int index, std::string new_value);
    std::string get_root() const;
    int get_leaf_count() const;
    std::vector<MerkleProofNode> get_auth_path(int index) const;
};

struct AuthToken {
    std::string user_gid;
    std::string zk_id;
    std::vector<std::string> attributes;
    std::string update_token;
    int nonce;
    std::int64_t issued_at_unix;
    int leaf_index;
    std::string registration_root;
    VersionTag issued_tag;
    std::string prover_state_path;
    std::string proof_file_path;
    std::string public_file_path;
    double prove_time_ms = 0.0;
    std::vector<uint8_t> signature;
};

struct ReEncryptionMaterial {
    int old_epoch;
    int new_epoch;
    std::string re_encryption_key;
    std::string update_token;
};

struct UserRecord {
    std::string user_gid;
    std::string zk_id;
    std::string registration_leaf;
    int leaf_index;
    bool is_revoked;
};

class IdentityAuthority {
private:
    std::filesystem::path state_directory;
    MerkleTree RegistrationTree;
    MerkleTree RevocationTree;
    std::unordered_map<std::string, UserRecord> users;
    std::string zk_registration_root;
    std::string zk_revocation_root;

    void* signer_handle;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;

    std::string real_poseidon_hash(std::string input) const;
    std::string build_default_revocation_leaf(int leaf_index) const;
    std::string build_auth_payload(const UserRecord& user,
                                   const VersionTag& tag,
                                   const std::string& registration_root,
                                   int nonce,
                                   std::int64_t issued_at_unix,
                                   const std::vector<std::string>& attributes) const;
    bool refresh_zk_roots();
    bool load_state();
    bool save_state() const;
    void rebuild_trees_from_users();

public:
    explicit IdentityAuthority(const std::filesystem::path& state_dir = "runtime/state/ia");
    ~IdentityAuthority();

    UserRecord register_user(std::string user_gid, int identity_secret);
    bool authenticate_user(const std::string& user_gid, AuthToken& token);
    bool authenticate_user(const std::string& user_gid, const std::vector<std::string>& attributes, AuthToken& token);
    bool get_registration_auth_path(const std::string& user_gid, std::vector<MerkleProofNode>& auth_path) const;
    bool revoke_user(const std::string& user_gid);
    bool is_registered(const std::string& user_gid) const;
    bool get_user_record(const std::string& user_gid, UserRecord& record) const;
    std::vector<UserRecord> list_user_records() const;
    const std::filesystem::path& get_state_directory() const;

    const std::vector<uint8_t>& get_public_key() const;
    size_t get_public_key_length() const;
    const char* get_signature_algorithm() const;
    std::string get_registration_root() const;
    std::string get_revocation_root() const;
    std::string serialize_auth_payload(const AuthToken& token) const;
};
