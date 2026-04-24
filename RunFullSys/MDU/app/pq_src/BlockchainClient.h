#pragma once

#include <string>
#include "Blockchain.h"

class BlockchainClient {
private:
    std::string cast_bin;
    std::string rpc_url;
    std::string contract_address;
    std::string private_key;

    std::string quote_argument(const std::string& value) const;
    std::string run_command_capture(const std::string& command) const;
    bool run_command(const std::string& command) const;

public:
    BlockchainClient();

    static std::string normalize_hex_bytes32(const std::string& value);
    static std::string decimal_to_hex_bytes32(const std::string& value);
    static std::string hex_bytes32_to_decimal(const std::string& value);
    bool is_configured() const;
    bool can_broadcast() const;
    bool get_current_state(VersionTag& state) const;
    bool bootstrap_genesis_roots(const std::string& registration_root,
                                 const std::string& revocation_root) const;
    bool update_registration_root(const std::string& registration_root) const;
    bool update_roots(int epoch,
                      const std::string& registration_root,
                      const std::string& revocation_root) const;
};
