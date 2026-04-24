#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "phase3_encrypt.h"

namespace abse_zkp {

struct ScenarioUserInput {
    std::string gid;
    int identity_secret = 0;
    bool has_identity_secret = false;
    std::vector<std::string> attributes;
};

struct ScenarioBundleInput {
    std::string label;
    std::string data_owner_gid;
    std::string plaintext;
    std::vector<std::string> keywords;
    std::string policy_expression;
    LogicalPolicy policy;
};

struct ScenarioQueryInput {
    std::string gid;
    std::string bundle_label;
    std::vector<std::string> keywords;
};

struct ScenarioRevocationInput {
    std::string gid;
};

struct TestScenario {
    std::map<std::string, ScenarioUserInput> users;
    std::map<std::string, ScenarioBundleInput> bundles;
    std::map<std::string, ScenarioQueryInput> queries;
    std::map<std::string, ScenarioRevocationInput> revocations;
};

std::filesystem::path DefaultScenarioPath();
TestScenario LoadTestScenario(const std::filesystem::path& path);
const ScenarioUserInput& GetScenarioUser(const TestScenario& scenario, const std::string& name);
const ScenarioBundleInput& GetScenarioBundle(const TestScenario& scenario, const std::string& name);
const ScenarioQueryInput& GetScenarioQuery(const TestScenario& scenario, const std::string& name);
const ScenarioRevocationInput& GetScenarioRevocation(const TestScenario& scenario, const std::string& name);

}  // namespace abse_zkp
