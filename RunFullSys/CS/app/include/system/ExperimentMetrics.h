#pragma once

#include <chrono>
#include <filesystem>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace abse_zkp {

using Clock = std::chrono::high_resolution_clock;
using TimePoint = Clock::time_point;

double ElapsedMilliseconds(const TimePoint& start, const TimePoint& end);
std::filesystem::path DefaultExperimentMetricsPath();
uintmax_t FileSizeOrZero(const std::filesystem::path& path);
bool AppendExperimentRow(const std::filesystem::path& path,
                         const std::vector<std::string>& header,
                         const std::vector<std::string>& row);
std::string ToCsvField(const std::string& value);
std::string ToCsvField(const char* value);
std::string ToCsvField(double value);
std::string ToCsvField(uintmax_t value);
std::string ToCsvField(int value);
std::string ToCsvField(bool value);

}  // namespace abse_zkp
