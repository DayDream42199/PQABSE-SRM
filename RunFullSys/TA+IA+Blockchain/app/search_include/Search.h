#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "phase3_encrypt.h"
#include "roaring.hh"

namespace abse_zkp {

std::string SerializeKeywordToken(const TrapdoorElement& token);
std::vector<std::string> SerializeKeywordTokens(const std::vector<TrapdoorElement>& tokens);
std::string BuildEpochBitmapKey(const std::string& serialized_token,
                                int epoch,
                                const std::string& epoch_bitmap_key);
std::vector<std::string> BuildEpochBitmapKeys(const std::vector<TrapdoorElement>& tokens,
                                              int epoch,
                                              const std::string& epoch_bitmap_key);

class SearchOptimizationLayer {
public:
    void AddKeywordToFile(const std::string& bitmap_key, uint32_t file_id);
    uint32_t ProcessNewUpload(const std::string& bundle_label,
                              const std::vector<TrapdoorElement>& secure_index,
                              int epoch,
                              const std::string& epoch_bitmap_key);
    void OptimizeAllBitmaps();
    roaring::Roaring ExecuteAdaptiveSearch(std::vector<std::string> bitmap_keys) const;
    roaring::Roaring PruneCandidates(std::vector<std::string> bitmap_keys) const;
    std::vector<std::string> ResolveLabels(const roaring::Roaring& candidate_ids) const;
    std::vector<std::string> KnownLabels() const;
    bool ContainsLabel(const std::string& bundle_label) const;
    bool SaveToFile(const std::filesystem::path& path) const;
    static bool LoadFromFile(const std::filesystem::path& path, SearchOptimizationLayer& index);

private:
    std::unordered_map<std::string, roaring::Roaring> inverted_index_;
    std::unordered_map<uint32_t, std::string> file_labels_;
    uint32_t next_file_id_ = 1;
    double threshold_tau_ = 5.0;
};

}  // namespace abse_zkp
