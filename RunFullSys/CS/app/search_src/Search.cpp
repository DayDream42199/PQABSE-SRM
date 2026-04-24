#include "Search.h"

#include <algorithm>
#include <fstream>
#include <openssl/sha.h>
#include <sstream>

namespace abse_zkp {
namespace {

constexpr const char* kSearchIndexMagic = "PQABSE_SEARCH_INDEX_V1";

uint64_t CoefficientToUint64(const TrapdoorElement::Integer& coefficient) {
    std::ostringstream out;
    out << coefficient;
    return std::stoull(out.str());
}

bool WriteString(std::ostream& out, const std::string& value) {
    const uint64_t size = static_cast<uint64_t>(value.size());
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));
    out.write(value.data(), static_cast<std::streamsize>(value.size()));
    return static_cast<bool>(out);
}

bool ReadString(std::istream& in, std::string& value) {
    uint64_t size = 0;
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (!in) {
        return false;
    }
    value.resize(static_cast<size_t>(size));
    in.read(value.data(), static_cast<std::streamsize>(size));
    return static_cast<bool>(in);
}

bool WriteBitmap(std::ostream& out, const roaring::Roaring& bitmap) {
    const uint64_t size = static_cast<uint64_t>(bitmap.getSizeInBytes(true));
    std::string buffer(static_cast<size_t>(size), '\0');
    bitmap.write(buffer.data(), true);
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));
    out.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    return static_cast<bool>(out);
}

bool ReadBitmap(std::istream& in, roaring::Roaring& bitmap) {
    uint64_t size = 0;
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (!in) {
        return false;
    }
    std::string buffer(static_cast<size_t>(size), '\0');
    in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    if (!in) {
        return false;
    }
    bitmap = roaring::Roaring::readSafe(buffer.data(), buffer.size());
    return true;
}

std::string Sha256Bytes(const std::string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    return std::string(reinterpret_cast<const char*>(digest), SHA256_DIGEST_LENGTH);
}

}  // namespace

std::string SerializeKeywordToken(const TrapdoorElement& token) {
    TrapdoorElement value = token;
    value.SetFormat(Format::COEFFICIENT);
    std::string serialized;
    serialized.reserve(static_cast<size_t>(value.GetLength()) * sizeof(uint64_t));
    for (uint32_t i = 0; i < value.GetLength(); ++i) {
        const uint64_t coefficient = CoefficientToUint64(value[i]);
        serialized.append(reinterpret_cast<const char*>(&coefficient), sizeof(coefficient));
    }
    return serialized;
}

std::vector<std::string> SerializeKeywordTokens(const std::vector<TrapdoorElement>& tokens) {
    std::vector<std::string> serialized;
    serialized.reserve(tokens.size());
    for (const auto& token : tokens) {
        serialized.push_back(SerializeKeywordToken(token));
    }
    return serialized;
}

std::string BuildEpochBitmapKey(const std::string& serialized_token,
                                int epoch,
                                const std::string& epoch_bitmap_key) {
    return Sha256Bytes("bitmap|epoch=" + std::to_string(epoch) +
                       "|secret=" + epoch_bitmap_key +
                       "|token=" + serialized_token);
}

std::vector<std::string> BuildEpochBitmapKeys(const std::vector<TrapdoorElement>& tokens,
                                              int epoch,
                                              const std::string& epoch_bitmap_key) {
    std::vector<std::string> keys;
    keys.reserve(tokens.size());
    for (const auto& serialized_token : SerializeKeywordTokens(tokens)) {
        keys.push_back(BuildEpochBitmapKey(serialized_token, epoch, epoch_bitmap_key));
    }
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    return keys;
}

void SearchOptimizationLayer::AddKeywordToFile(const std::string& bitmap_key, uint32_t file_id) {
    inverted_index_[bitmap_key].add(file_id);
}

uint32_t SearchOptimizationLayer::ProcessNewUpload(const std::string& bundle_label,
                                                   const std::vector<TrapdoorElement>& secure_index,
                                                   int epoch,
                                                   const std::string& epoch_bitmap_key) {
    const uint32_t assigned_file_id = next_file_id_++;
    file_labels_[assigned_file_id] = bundle_label;
    for (const auto& bitmap_key : BuildEpochBitmapKeys(secure_index, epoch, epoch_bitmap_key)) {
        AddKeywordToFile(bitmap_key, assigned_file_id);
    }
    return assigned_file_id;
}

void SearchOptimizationLayer::OptimizeAllBitmaps() {
    for (auto& entry : inverted_index_) {
        entry.second.runOptimize();
    }
}

roaring::Roaring SearchOptimizationLayer::PruneCandidates(std::vector<std::string> bitmap_keys) const {
    if (bitmap_keys.empty()) {
        return roaring::Roaring();
    }

    for (const auto& bitmap_key : bitmap_keys) {
        if (inverted_index_.find(bitmap_key) == inverted_index_.end()) {
            return roaring::Roaring();
        }
    }

    std::sort(bitmap_keys.begin(), bitmap_keys.end(), [this](const std::string& lhs, const std::string& rhs) {
        return inverted_index_.at(lhs).cardinality() < inverted_index_.at(rhs).cardinality();
    });

    roaring::Roaring candidate_set = inverted_index_.at(bitmap_keys.front());
    for (size_t i = 1; i < bitmap_keys.size(); ++i) {
        candidate_set &= inverted_index_.at(bitmap_keys[i]);
    }
    return candidate_set;
}

roaring::Roaring SearchOptimizationLayer::ExecuteAdaptiveSearch(std::vector<std::string> bitmap_keys) const {
    if (bitmap_keys.empty()) {
        return roaring::Roaring();
    }

    for (const auto& bitmap_key : bitmap_keys) {
        if (inverted_index_.find(bitmap_key) == inverted_index_.end()) {
            return roaring::Roaring();
        }
    }

    double total_cardinality = 0.0;
    for (const auto& bitmap_key : bitmap_keys) {
        total_cardinality += static_cast<double>(inverted_index_.at(bitmap_key).cardinality());
    }
    const double average_cardinality = total_cardinality / static_cast<double>(bitmap_keys.size());
    const double query_complexity = static_cast<double>(bitmap_keys.size()) * average_cardinality;

    if (query_complexity < threshold_tau_) {
        std::sort(bitmap_keys.begin(), bitmap_keys.end(), [this](const std::string& lhs, const std::string& rhs) {
            return inverted_index_.at(lhs).cardinality() < inverted_index_.at(rhs).cardinality();
        });
        return inverted_index_.at(bitmap_keys.front());
    }

    return PruneCandidates(std::move(bitmap_keys));
}

std::vector<std::string> SearchOptimizationLayer::ResolveLabels(const roaring::Roaring& candidate_ids) const {
    std::vector<uint32_t> ids(candidate_ids.cardinality());
    if (!ids.empty()) {
        candidate_ids.toUint32Array(ids.data());
    }

    std::vector<std::string> labels;
    labels.reserve(ids.size());
    for (uint32_t id : ids) {
        const auto it = file_labels_.find(id);
        if (it != file_labels_.end()) {
            labels.push_back(it->second);
        }
    }
    return labels;
}

std::vector<std::string> SearchOptimizationLayer::KnownLabels() const {
    std::vector<std::pair<uint32_t, std::string>> ordered(file_labels_.begin(), file_labels_.end());
    std::sort(ordered.begin(), ordered.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.first < rhs.first;
    });

    std::vector<std::string> labels;
    labels.reserve(ordered.size());
    for (const auto& entry : ordered) {
        labels.push_back(entry.second);
    }
    std::sort(labels.begin(), labels.end());
    return labels;
}

bool SearchOptimizationLayer::ContainsLabel(const std::string& bundle_label) const {
    return std::any_of(file_labels_.begin(), file_labels_.end(), [&](const auto& entry) {
        return entry.second == bundle_label;
    });
}

bool SearchOptimizationLayer::SaveToFile(const std::filesystem::path& path) const {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    if (!WriteString(out, kSearchIndexMagic)) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(&next_file_id_), sizeof(next_file_id_));
    out.write(reinterpret_cast<const char*>(&threshold_tau_), sizeof(threshold_tau_));
    if (!out) {
        return false;
    }

    const uint64_t label_count = static_cast<uint64_t>(file_labels_.size());
    out.write(reinterpret_cast<const char*>(&label_count), sizeof(label_count));
    if (!out) {
        return false;
    }

    std::vector<std::pair<uint32_t, std::string>> ordered_labels(file_labels_.begin(), file_labels_.end());
    std::sort(ordered_labels.begin(), ordered_labels.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.first < rhs.first;
    });
    for (const auto& entry : ordered_labels) {
        out.write(reinterpret_cast<const char*>(&entry.first), sizeof(entry.first));
        if (!out || !WriteString(out, entry.second)) {
            return false;
        }
    }

    const uint64_t keyword_count = static_cast<uint64_t>(inverted_index_.size());
    out.write(reinterpret_cast<const char*>(&keyword_count), sizeof(keyword_count));
    if (!out) {
        return false;
    }

    std::vector<std::pair<std::string, roaring::Roaring>> ordered_index(inverted_index_.begin(), inverted_index_.end());
    std::sort(ordered_index.begin(), ordered_index.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.first < rhs.first;
    });
    for (const auto& entry : ordered_index) {
        if (!WriteString(out, entry.first) || !WriteBitmap(out, entry.second)) {
            return false;
        }
    }

    return static_cast<bool>(out);
}

bool SearchOptimizationLayer::LoadFromFile(const std::filesystem::path& path, SearchOptimizationLayer& index) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    SearchOptimizationLayer loaded;
    std::string magic;
    if (!ReadString(in, magic) || magic != kSearchIndexMagic) {
        return false;
    }
    in.read(reinterpret_cast<char*>(&loaded.next_file_id_), sizeof(loaded.next_file_id_));
    in.read(reinterpret_cast<char*>(&loaded.threshold_tau_), sizeof(loaded.threshold_tau_));
    if (!in) {
        return false;
    }

    uint64_t label_count = 0;
    in.read(reinterpret_cast<char*>(&label_count), sizeof(label_count));
    if (!in) {
        return false;
    }
    for (uint64_t i = 0; i < label_count; ++i) {
        uint32_t file_id = 0;
        std::string label;
        in.read(reinterpret_cast<char*>(&file_id), sizeof(file_id));
        if (!in || !ReadString(in, label)) {
            return false;
        }
        loaded.file_labels_[file_id] = std::move(label);
    }

    uint64_t keyword_count = 0;
    in.read(reinterpret_cast<char*>(&keyword_count), sizeof(keyword_count));
    if (!in) {
        return false;
    }
    for (uint64_t i = 0; i < keyword_count; ++i) {
        std::string keyword;
        roaring::Roaring bitmap;
        if (!ReadString(in, keyword) || !ReadBitmap(in, bitmap)) {
            return false;
        }
        loaded.inverted_index_[std::move(keyword)] = std::move(bitmap);
    }

    index = std::move(loaded);
    return true;
}

}  // namespace abse_zkp
