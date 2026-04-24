#include "Blockchain.h"
#include "BlockchainClient.h"

#include <filesystem>
#include <fstream>
#include <map>

namespace {

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

std::filesystem::path local_state_path() {
    return find_workspace_root() / "runtime" / "state" / "blockchain_state.txt";
}

std::string trim(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    std::size_t start = 0;
    while (start < value.size() && (value[start] == ' ' || value[start] == '\t' || value[start] == '\n' || value[start] == '\r')) {
        ++start;
    }
    return value.substr(start);
}

const std::string& zero_root_hex() {
    static const std::string value = BlockchainClient::normalize_hex_bytes32("0x0");
    return value;
}

BlockchainClient& chain_client() {
    static BlockchainClient client;
    return client;
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
        values[trim(line.substr(0, pos))] = trim(line.substr(pos + 1));
    }
    return values;
}

}

BlockchainLedger Blockchain;

BlockchainLedger::BlockchainLedger() {
    load_local_state();
}

bool BlockchainLedger::matches_current_state(const VersionTag& other) const {
    return current_state.epoch == other.epoch &&
           current_state.registration_root == other.registration_root &&
           current_state.revocation_root == other.revocation_root;
}

void BlockchainLedger::append_log_entry_if_changed(const std::string& note) {
    if (!state_log.empty()) {
        const auto& last = state_log.back();
        if (last.epoch == current_state.epoch &&
            last.registration_root == current_state.registration_root &&
            last.revocation_root == current_state.revocation_root) {
            return;
        }
    }
    state_log.push_back({current_state.epoch, current_state.registration_root, current_state.revocation_root, note});
}

bool BlockchainLedger::load_local_state() {
    const auto path = local_state_path();
    if (!std::filesystem::exists(path)) {
        return false;
    }
    const auto values = load_key_values(path);
    if (values.empty()) {
        return false;
    }

    VersionTag loaded{};
    if (const auto it = values.find("epoch"); it != values.end()) {
        loaded.epoch = std::stoi(it->second);
    }
    if (const auto it = values.find("registration_root"); it != values.end()) {
        loaded.registration_root = BlockchainClient::normalize_hex_bytes32(it->second);
    }
    if (const auto it = values.find("revocation_root"); it != values.end()) {
        loaded.revocation_root = BlockchainClient::normalize_hex_bytes32(it->second);
    }

    current_state = loaded;
    append_log_entry_if_changed("loaded from local state");
    return true;
}

void BlockchainLedger::save_local_state() const {
    const auto path = local_state_path();
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::trunc);
    output << "epoch=" << current_state.epoch << '\n';
    output << "registration_root=" << current_state.registration_root << '\n';
    output << "revocation_root=" << current_state.revocation_root << '\n';
}

void VersionTag::print() const {
    std::cout << "[Epoch: " << epoch
              << " | Registration Root: " << registration_root
              << " | Revocation Root: " << revocation_root << "]";
}

void BlockchainLedger::update_state(int new_epoch, std::string new_root, std::string note) {
    update_state(new_epoch, current_state.registration_root, std::move(new_root), std::move(note));
}

void BlockchainLedger::update_state(int new_epoch,
                                    std::string new_registration_root,
                                    std::string new_revocation_root,
                                    std::string note) {
    const VersionTag desired_state{new_epoch,
                                   BlockchainClient::normalize_hex_bytes32(new_registration_root),
                                   BlockchainClient::normalize_hex_bytes32(new_revocation_root)};
    const bool changed = !matches_current_state(desired_state);

    current_state = desired_state;
    append_log_entry_if_changed(note);
    save_local_state();

    if (changed) {
        std::cout << "[Blockchain] State updated to Epoch " << new_epoch << std::endl;
    }

    VersionTag chain_state{};
    if (!chain_client().get_current_state(chain_state)) {
        return;
    }

    if (chain_state.epoch > current_state.epoch) {
        return;
    }

    if (matches_current_state(chain_state)) {
        return;
    }

    if (chain_state.epoch == 0 && current_state.epoch == 0 &&
        chain_state.registration_root == zero_root_hex() &&
        chain_state.revocation_root == zero_root_hex()) {
        if (chain_client().bootstrap_genesis_roots(current_state.registration_root, current_state.revocation_root)) {
            std::cout << "[Blockchain] On-chain genesis roots bootstrapped successfully." << std::endl;
        }
        return;
    }

    if (chain_state.epoch == current_state.epoch &&
        chain_state.revocation_root == current_state.revocation_root &&
        chain_state.registration_root != current_state.registration_root) {
        if (chain_client().update_registration_root(current_state.registration_root)) {
            std::cout << "[Blockchain] On-chain registration root updated successfully." << std::endl;
        }
        return;
    }

    if (chain_client().update_roots(current_state.epoch,
                                    current_state.registration_root,
                                    current_state.revocation_root)) {
        std::cout << "[Blockchain] On-chain roots updated successfully." << std::endl;
    }
}

bool BlockchainLedger::sync_from_chain() {
    VersionTag chain_state{};
    if (chain_client().get_current_state(chain_state)) {
        const bool changed = !matches_current_state(chain_state);
        current_state = chain_state;
        if (changed) {
            append_log_entry_if_changed("synced from on-chain state");
            save_local_state();
        }
        return true;
    }
    return load_local_state();
}

bool BlockchainLedger::has_meaningful_local_log() const {
    if (state_log.empty()) {
        return false;
    }
    if (state_log.size() == 1 && state_log.front().note == "loaded from local state") {
        return false;
    }
    return true;
}

void BlockchainLedger::print_log() const {
    std::cout << "\n--- Blockchain State Log ---" << std::endl;
    for (const auto& entry : state_log) {
        std::cout << "  Epoch " << entry.epoch
                  << " | Registration Root: " << entry.registration_root
                  << " | Revocation Root: " << entry.revocation_root
                  << " | Note: " << entry.note << std::endl;
    }
}
