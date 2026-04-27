#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "system/Cli.h"
#include "system/RuntimePaths.h"

namespace {

using namespace abse_zkp;

std::string Quote(const std::filesystem::path& value) {
    return "\"" + value.string() + "\"";
}

std::string Quote(const std::string& value) {
    return "\"" + value + "\"";
}

int RunCommand(const std::string& command) {
    std::cout << "$ " << command << '\n';
    return std::system(command.c_str());
}

std::filesystem::path ExecutableDirectory(const char* argv0) {
    std::error_code ec;
    auto path = std::filesystem::weakly_canonical(std::filesystem::path(argv0), ec);
    if (ec) {
        path = std::filesystem::absolute(std::filesystem::path(argv0), ec);
    }
    return path.parent_path();
}

void EnsureSuccess(const std::string& label, int exit_code) {
    if (exit_code != 0) {
        throw std::runtime_error(label + " failed with exit code " + std::to_string(exit_code));
    }
}

}  // namespace

int main(int argc, char** argv) {
    using namespace abse_zkp;
    CliArgs cli(argc, argv);
    EnsureRuntimeDirectories();

    const auto exe_dir = ExecutableDirectory(argv[0]);
    const std::string run_label = cli.Get("--run-label", "synthetic_run");
    const auto scenario_path =
        std::filesystem::path(cli.Get("--scenario-out", (WorkspaceRoot() / "config" / (run_label + ".conf")).string()));
    const auto results_dir =
        std::filesystem::path(cli.Get("--results-dir", (ExperimentArtifactRoot() / run_label).string()));
    std::filesystem::create_directories(results_dir);

    const auto generate_exe = exe_dir / "generate_synthetic_scenario";
    const auto materialize_exe = exe_dir / "materialize_scenario";
    const auto search_exe = exe_dir / "search_benchmark_sweep";
    const auto encryption_exe = exe_dir / "encryption_benchmark_sweep";
    const auto revocation_exe = exe_dir / "revocation_benchmark_sweep";

    std::ostringstream generate;
    generate << Quote(generate_exe)
             << " --output " << Quote(scenario_path)
             << " --users " << Quote(cli.Get("--users", "20"))
             << " --bundles " << Quote(cli.Get("--bundles", "100"))
             << " --keyword-pool " << Quote(cli.Get("--keyword-pool", "200"))
             << " --keywords-per-bundle " << Quote(cli.Get("--keywords-per-bundle", "50"))
             << " --common-keywords " << Quote(cli.Get("--common-keywords", "20"))
             << " --medium-keywords " << Quote(cli.Get("--medium-keywords", "60"))
             << " --rare-keywords " << Quote(cli.Get("--rare-keywords", "80"))
             << " --common-per-bundle " << Quote(cli.Get("--common-per-bundle", "8"))
             << " --medium-per-bundle " << Quote(cli.Get("--medium-per-bundle", "20"))
             << " --rare-per-bundle " << Quote(cli.Get("--rare-per-bundle", "12"))
             << " --selective-per-bundle " << Quote(cli.Get("--selective-per-bundle", "10"))
             << " --selective-cluster-span " << Quote(cli.Get("--selective-cluster-span", "8"))
             << " --attribute-pool " << Quote(cli.Get("--attribute-pool", "50"))
             << " --attrs-per-user " << Quote(cli.Get("--attrs-per-user", "20"))
             << " --attrs-per-policy " << Quote(cli.Get("--attrs-per-policy", "10"))
             << " --query-sizes " << Quote(cli.Get("--query-sizes", "10,20,50"))
             << " --queries-per-size " << Quote(cli.Get("--queries-per-size", "3"))
             << " --revocations " << Quote(cli.Get("--revocations", "3"))
             << " --policy-type " << Quote(cli.Get("--policy-type", "and"))
             << " --seed " << Quote(cli.Get("--seed", "1337"));
    if (!cli.Get("--threshold").empty()) {
        generate << " --threshold " << Quote(cli.Get("--threshold"));
    }

    std::ostringstream materialize;
    materialize << Quote(materialize_exe)
                << " --scenario " << Quote(scenario_path)
                << " --init-phase1-if-missing";
    if (cli.HasFlag("--rebuild-user-keys")) {
        materialize << " --rebuild-user-keys";
    }

    std::ostringstream search;
    search << Quote(search_exe)
           << " --scenario " << Quote(scenario_path)
           << " --metrics-out " << Quote((results_dir / "search_benchmark_sweep.csv").string())
           << " --aggregate-out " << Quote((results_dir / "search_benchmark_sweep_aggregate.csv").string())
           << " --query-sizes " << Quote(cli.Get("--query-sizes", "10,20,50"))
           << " --limit-per-size " << Quote(cli.Get("--search-limit-per-size", "0"))
           << " --provision-users";
    if (cli.HasFlag("--respect-policy")) {
        search << " --respect-policy";
    }
    if (cli.HasFlag("--decrypt")) {
        search << " --decrypt";
    }
    if (cli.HasFlag("--rebuild-index-each")) {
        search << " --rebuild-index-each";
    }

    std::ostringstream encryption;
    encryption << Quote(encryption_exe)
               << " --scenario " << Quote(scenario_path)
               << " --metrics-out " << Quote((results_dir / "encryption_benchmark_sweep.csv").string())
               << " --user-aggregate-out " << Quote((results_dir / "encryption_user_aggregate.csv").string())
               << " --bundle-aggregate-out " << Quote((results_dir / "encryption_bundle_aggregate.csv").string())
               << " --rebuild-index";

    std::ostringstream revocation;
    revocation << Quote(revocation_exe)
               << " --scenario " << Quote(scenario_path)
               << " --metrics-out " << Quote((results_dir / "revocation_benchmark_sweep.csv").string())
               << " --aggregate-out " << Quote((results_dir / "revocation_benchmark_sweep_aggregate.csv").string())
               << " --limit " << Quote(cli.Get("--revocation-limit", "0"));

    EnsureSuccess("generate_synthetic_scenario", RunCommand(generate.str()));
    EnsureSuccess("materialize_scenario", RunCommand(materialize.str()));
    EnsureSuccess("search_benchmark_sweep", RunCommand(search.str()));
    EnsureSuccess("encryption_benchmark_sweep", RunCommand(encryption.str()));
    EnsureSuccess("revocation_benchmark_sweep", RunCommand(revocation.str()));

    std::cout << "Benchmark orchestration complete." << '\n';
    std::cout << "Scenario: " << scenario_path << '\n';
    std::cout << "Results directory: " << results_dir << '\n';
    return 0;
}
