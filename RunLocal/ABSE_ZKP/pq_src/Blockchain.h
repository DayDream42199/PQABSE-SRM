#pragma once

#include <string>
#include <vector>
#include <iostream>

struct VersionTag {
    int epoch = 0;
    std::string registration_root = "0x0000000000000000000000000000000000000000000000000000000000000000";
    std::string revocation_root = "0x0000000000000000000000000000000000000000000000000000000000000000";

    void print() const;
};

struct BlockchainLogEntry {
    int epoch;
    std::string registration_root;
    std::string revocation_root;
    std::string note;
};

class BlockchainLedger {
public:
    VersionTag current_state;
    std::vector<BlockchainLogEntry> state_log;

    BlockchainLedger();

    void update_state(int new_epoch, std::string new_root, std::string note = "state update");
    void update_state(int new_epoch,
                      std::string new_registration_root,
                      std::string new_revocation_root,
                      std::string note);
    bool sync_from_chain();
    void print_log() const;
    bool has_meaningful_local_log() const;

private:
    void append_log_entry_if_changed(const std::string& note);
    bool matches_current_state(const VersionTag& other) const;
    bool load_local_state();
    void save_local_state() const;
};

extern BlockchainLedger Blockchain;
