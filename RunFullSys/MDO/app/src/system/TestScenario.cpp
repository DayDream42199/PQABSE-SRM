#include "system/TestScenario.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "entities/SoftwareTee.h"
#include "system/RuntimePaths.h"

namespace abse_zkp {
namespace {

std::string Trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    return value.substr(start);
}

std::vector<std::string> Split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    std::istringstream input(value);
    while (std::getline(input, current, delimiter)) {
        parts.push_back(current);
    }
    return parts;
}

std::vector<std::string> SplitCsv(const std::string& value) {
    std::vector<std::string> parts;
    for (const auto& part : Split(value, ',')) {
        const auto trimmed = Trim(part);
        if (!trimmed.empty()) {
            parts.push_back(trimmed);
        }
    }
    return parts;
}

[[noreturn]] void ThrowConfigError(const std::filesystem::path& path, std::size_t line_no, const std::string& message) {
    throw std::runtime_error("Scenario config error in " + path.string() + ":" + std::to_string(line_no) + ": " + message);
}

}  // namespace

std::filesystem::path DefaultScenarioPath() {
    return WorkspaceRoot() / "config" / "test_demo_1.conf";
}

TestScenario LoadTestScenario(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Failed to open scenario config: " + path.string());
    }

    TestScenario scenario;
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(input, line)) {
        ++line_no;
        const auto comment = line.find('#');
        if (comment != std::string::npos) {
            line = line.substr(0, comment);
        }
        line = Trim(line);
        if (line.empty()) {
            continue;
        }

        const auto split = line.find('=');
        if (split == std::string::npos) {
            ThrowConfigError(path, line_no, "expected key=value entry");
        }

        const auto key = Trim(line.substr(0, split));
        const auto value = Trim(line.substr(split + 1));
        const auto parts = Split(key, '.');
        if (parts.size() != 3) {
            ThrowConfigError(path, line_no, "expected keys shaped like user.Alice.attributes or bundle.demo1.policy");
        }

        const auto& category = parts[0];
        const auto& name = parts[1];
        const auto& field = parts[2];

        if (category == "user") {
            auto& user = scenario.users[name];
            if (user.gid.empty()) {
                user.gid = name;
            }
            if (field == "gid") {
                user.gid = value;
            } else if (field == "identity_secret") {
                user.identity_secret = std::stoi(value);
                user.has_identity_secret = true;
            } else if (field == "attributes") {
                user.attributes = SplitCsv(value);
            } else {
                ThrowConfigError(path, line_no, "unsupported user field: " + field);
            }
            continue;
        }

        if (category == "bundle") {
            auto& bundle = scenario.bundles[name];
            if (bundle.label.empty()) {
                bundle.label = name;
            }
            if (field == "label") {
                bundle.label = value;
            } else if (field == "data_owner_gid") {
                bundle.data_owner_gid = value;
            } else if (field == "plaintext") {
                bundle.plaintext = value;
            } else if (field == "keywords") {
                bundle.keywords = SplitCsv(value);
            } else if (field == "policy") {
                bundle.policy_expression = value;
            } else {
                ThrowConfigError(path, line_no, "unsupported bundle field: " + field);
            }
            continue;
        }

        if (category == "query") {
            auto& query = scenario.queries[name];
            if (field == "gid") {
                query.gid = value;
            } else if (field == "bundle_label") {
                query.bundle_label = value;
            } else if (field == "keywords") {
                query.keywords = SplitCsv(value);
            } else {
                ThrowConfigError(path, line_no, "unsupported query field: " + field);
            }
            continue;
        }

        if (category == "revocation") {
            auto& revocation = scenario.revocations[name];
            if (field == "gid") {
                revocation.gid = value;
            } else {
                ThrowConfigError(path, line_no, "unsupported revocation field: " + field);
            }
            continue;
        }

        ThrowConfigError(path, line_no, "unsupported category: " + category);
    }

    for (auto& [name, user] : scenario.users) {
        if (user.gid.empty()) {
            user.gid = name;
        }
        if (user.attributes.empty()) {
            throw std::runtime_error("Scenario user '" + name + "' is missing attributes");
        }
    }

    for (auto& [name, bundle] : scenario.bundles) {
        if (bundle.label.empty()) {
            bundle.label = name;
        }
        if (bundle.data_owner_gid.empty()) {
            throw std::runtime_error("Scenario bundle '" + name + "' is missing data_owner_gid");
        }
        if (bundle.plaintext.empty()) {
            throw std::runtime_error("Scenario bundle '" + name + "' is missing plaintext");
        }
        if (bundle.keywords.empty()) {
            throw std::runtime_error("Scenario bundle '" + name + "' is missing keywords");
        }
        if (bundle.policy_expression.empty()) {
            throw std::runtime_error("Scenario bundle '" + name + "' is missing policy");
        }
        bundle.policy = BuildLogicalPolicyFromExpression(bundle.policy_expression);
    }

    for (const auto& [name, query] : scenario.queries) {
        if (query.gid.empty() || query.bundle_label.empty() || query.keywords.empty()) {
            throw std::runtime_error("Scenario query '" + name + "' is incomplete");
        }
    }

    for (const auto& [name, revocation] : scenario.revocations) {
        if (revocation.gid.empty()) {
            throw std::runtime_error("Scenario revocation '" + name + "' is missing gid");
        }
    }

    return scenario;
}

const ScenarioUserInput& GetScenarioUser(const TestScenario& scenario, const std::string& name) {
    const auto it = scenario.users.find(name);
    if (it == scenario.users.end()) {
        throw std::runtime_error("Unknown scenario user: " + name);
    }
    return it->second;
}

const ScenarioBundleInput& GetScenarioBundle(const TestScenario& scenario, const std::string& name) {
    const auto it = scenario.bundles.find(name);
    if (it == scenario.bundles.end()) {
        throw std::runtime_error("Unknown scenario bundle: " + name);
    }
    return it->second;
}

const ScenarioQueryInput& GetScenarioQuery(const TestScenario& scenario, const std::string& name) {
    const auto it = scenario.queries.find(name);
    if (it == scenario.queries.end()) {
        throw std::runtime_error("Unknown scenario query: " + name);
    }
    return it->second;
}

const ScenarioRevocationInput& GetScenarioRevocation(const TestScenario& scenario, const std::string& name) {
    const auto it = scenario.revocations.find(name);
    if (it == scenario.revocations.end()) {
        throw std::runtime_error("Unknown scenario revocation: " + name);
    }
    return it->second;
}

}  // namespace abse_zkp
