#include "system/ExperimentMetrics.h"

#include <fstream>
#include <iomanip>
#include <sstream>

#include "system/RuntimePaths.h"

namespace abse_zkp {

double ElapsedMilliseconds(const TimePoint& start, const TimePoint& end) {
    return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - start).count();
}

std::filesystem::path DefaultExperimentMetricsPath() {
    return ExperimentArtifactRoot() / "phase_metrics.csv";
}

uintmax_t FileSizeOrZero(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) {
        return 0;
    }
    const auto size = std::filesystem::file_size(path, ec);
    return ec ? 0 : size;
}

bool AppendExperimentRow(const std::filesystem::path& path,
                         const std::vector<std::string>& header,
                         const std::vector<std::string>& row) {
    if (header.size() != row.size()) {
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    const bool write_header = !std::filesystem::exists(path, ec) || ec;

    std::ofstream output(path, std::ios::app);
    if (!output.is_open()) {
        return false;
    }

    auto write_record = [&output](const std::vector<std::string>& values) {
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) {
                output << ',';
            }
            output << values[i];
        }
        output << '\n';
    };

    if (write_header) {
        write_record(header);
    }
    write_record(row);
    return static_cast<bool>(output);
}

std::string ToCsvField(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (char ch : value) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

std::string ToCsvField(const char* value) {
    return ToCsvField(std::string(value == nullptr ? "" : value));
}

std::string ToCsvField(double value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(3) << value;
    return out.str();
}

std::string ToCsvField(uintmax_t value) {
    return std::to_string(value);
}

std::string ToCsvField(int value) {
    return std::to_string(value);
}

std::string ToCsvField(bool value) {
    return value ? "1" : "0";
}

}  // namespace abse_zkp
