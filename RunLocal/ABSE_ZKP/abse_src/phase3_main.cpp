#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "phase3_encrypt.h"

using namespace std;

namespace {

const string kOutputRoot = "Output";
const string kReadableDir = kOutputRoot + "/Readable";
const string kBinaryDir = kOutputRoot + "/Binary";

struct OwnerRecord {
    string label;
    string plaintext;
    vector<string> keywords;
    LogicalPolicy policy;
    string version_tag;
};

string FormatElementReadable(TrapdoorElement element) {
    element.SetFormat(Format::COEFFICIENT);
    ostringstream out;
    out << '[';
    for (uint32_t i = 0; i < element.GetLength(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << element[i];
    }
    out << ']';
    return out.str();
}

string FormatPolicyReadable(const AccessPolicy& policy) {
    ostringstream out;
    out << "descriptor = " << policy.descriptor << "\n";
    out << "summary_mode = " << (policy.is_summary ? 1 : 0) << "\n";
    out << "M = [\n";
    for (size_t row = 0; row < policy.matrix.size(); ++row) {
        out << "  [";
        for (size_t col = 0; col < policy.matrix[row].size(); ++col) {
            if (col != 0) {
                out << ", ";
            }
            out << policy.matrix[row][col];
        }
        out << "]";
        if (row + 1 != policy.matrix.size()) {
            out << ',';
        }
        out << '\n';
    }
    out << "]\n";
    out << "rho = [";
    for (size_t i = 0; i < policy.rho.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << policy.rho[i];
    }
    out << ']';
    return out.str();
}

string ToHex(const vector<unsigned char>& bytes) {
    ostringstream out;
    out << hex << setfill('0');
    for (unsigned char byte : bytes) {
        out << setw(2) << static_cast<int>(byte);
    }
    return out.str();
}

template <size_t N>
string ToHex(const array<unsigned char, N>& bytes) {
    return ToHex(vector<unsigned char>(bytes.begin(), bytes.end()));
}

bool WriteReadableCiphertextBundle(const string& plaintext, const CiphertextBundle& bundle, const string& path) {
    ofstream out(path);
    if (!out.is_open()) {
        return false;
    }

    out << "bundle_label:\n" << bundle.bundle_label << "\n\n";
    out << "plaintext:\n" << plaintext << "\n\n";
    out << "logical_policy:\n" << DescribeLogicalPolicy(bundle.logical_policy) << "\n\n";
    out << "derived_access_policy:\n" << FormatPolicyReadable(bundle.policy) << "\n\n";
    out << "version_tag:\n" << bundle.version_tag << "\n\n";
    out << "keyword_set:\n[";
    for (size_t i = 0; i < bundle.keyword_set.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << bundle.keyword_set[i];
    }
    out << "]\n\n";
    out << "ctdata_round_trip_verified:\n" << (bundle.ctdata_verified ? "PASS" : "FAIL") << "\n\n";
    out << "file_nonce_hex:\n" << ToHex(bundle.file_nonce) << "\n\n";
    out << "CTdata_nonce_hex:\n" << ToHex(bundle.nonce) << "\n\n";
    out << "CTdata_ciphertext_hex:\n" << ToHex(bundle.ctdata) << "\n\n";
    out << "tau_hex:\n" << ToHex(bundle.auth_tag) << "\n\n";
    out << "CTK.policy_tag:\n" << FormatElementReadable(bundle.ctk.policy_tag) << "\n\n";
    out << "CTK.header_u:\n" << FormatElementReadable(bundle.ctk.header_u) << "\n\n";
    out << "CTK.encrypted_session_key_hex:\n" << ToHex(bundle.ctk.encrypted_session_key) << "\n\n";
    out << "IW:\n[\n";
    for (size_t i = 0; i < bundle.secure_index.size(); ++i) {
        out << "  " << FormatElementReadable(bundle.secure_index[i]);
        if (i + 1 != bundle.secure_index.size()) {
            out << ',';
        }
        out << '\n';
    }
    out << "]\n";
    return true;
}

bool WriteBundleSummary(const CiphertextBundle& bundle, const string& path) {
    ofstream out(path);
    if (!out.is_open()) {
        return false;
    }

    out << "bundle_label=" << bundle.bundle_label << '\n';
    out << "logical_policy=" << DescribeLogicalPolicy(bundle.logical_policy) << '\n';
    out << "policy_rows=" << bundle.policy.matrix.size() << '\n';
    out << "policy_cols=" << (bundle.policy.matrix.empty() ? 0 : bundle.policy.matrix.front().size()) << '\n';
    out << "keyword_count=" << bundle.keyword_set.size() << '\n';
    out << "ctdata_bytes=" << bundle.ctdata.size() << '\n';
    out << "tau_bytes=" << bundle.auth_tag.size() << '\n';
    out << "iw_count=" << bundle.secure_index.size() << '\n';
    out << "version_tag=" << bundle.version_tag << '\n';
    out << "ctdata_round_trip_verified=" << (bundle.ctdata_verified ? 1 : 0) << '\n';
    return true;
}

vector<OwnerRecord> BuildOwnerRecords() {
    vector<OwnerRecord> records;

    records.push_back(OwnerRecord{
        "Gooning",
        "Gooning Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus vehicula, nisl non ultricies facilisis, lectus erat hendrerit elit, sed vulputate lorem risus eget urna. Integer non sem sit amet enim tempus suscipit. Donec vitae tortor nec nulla cursus feugiat.",
        {"Goon", "Document"},
        MakeAndPolicy(vector<LogicalPolicy>{
            MakeOrPolicy(vector<LogicalPolicy>{MakeAttributePolicy("Black"), MakeAttributePolicy("Asian")}),
            MakeAttributePolicy("Smart")
        }),
        "local-epoch-0"
    });

    records.push_back(OwnerRecord{
        "IngCar",
        "Car Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus vehicula, nisl non ultricies facilisis, lectus erat hendrerit elit, sed vulputate lorem risus eget urna. Integer non sem sit amet enim tempus suscipit. Donec vitae tortor nec nulla cursus feugiat.",
        {"Car", "Dick"},
        MakeAndPolicy(vector<LogicalPolicy>{MakeAttributePolicy("CPE"), MakeAttributePolicy("Asian")}),
        "local-epoch-0"
    });

    return records;
}

}  // namespace

int main() {
    SystemParams params{};
    PK pk;
    MSK msk;

    if (!LoadPhase1Artifacts(params, pk, msk, kBinaryDir)) {
        cerr << "Failed to load Phase 1 artifacts from build/" << kBinaryDir
             << ". Run ./phase1_setup first." << '\n';
        return 1;
    }

    std::filesystem::create_directories(kReadableDir);
    std::filesystem::create_directories(kBinaryDir);

    const auto records = BuildOwnerRecords();
    for (const auto& record : records) {
        CiphertextBundle bundle;
        try {
            AssembleCiphertextBundle(params, pk, record.label, record.plaintext, record.keywords,
                                     record.policy, record.version_tag, bundle);
        } catch (const exception& ex) {
            cerr << "Phase 3 assembly failed for " << record.label << ": " << ex.what() << '\n';
            return 2;
        }

        if (!SaveCiphertextBundle(params, bundle, kBinaryDir + "/" + record.label + "_ciphertext_bundle.bin")) {
            cerr << "Failed to save Phase 3 ciphertext bundle binary artifact for " << record.label << '\n';
            return 3;
        }
        if (!WriteReadableCiphertextBundle(record.plaintext, bundle,
                                           kReadableDir + "/" + record.label + "_ciphertext_bundle_readable.txt")) {
            cerr << "Failed to save Phase 3 readable bundle artifact for " << record.label << '\n';
            return 3;
        }
        if (!WriteBundleSummary(bundle, kReadableDir + "/" + record.label + "_ciphertext_bundle_summary.txt")) {
            cerr << "Failed to save Phase 3 bundle summary artifact for " << record.label << '\n';
            return 3;
        }

        cout << "[*] Phase 3 ciphertext bundle complete for " << record.label << '\n';
        cout << "Logical policy: " << DescribeLogicalPolicy(record.policy) << '\n';
        cout << "Derived matrix dimensions: " << bundle.policy.matrix.size() << " x "
             << (bundle.policy.matrix.empty() ? 0 : bundle.policy.matrix.front().size()) << '\n';
        cout << "Keyword count: " << bundle.keyword_set.size() << '\n';
        cout << "CTdata round-trip verification: " << (bundle.ctdata_verified ? "PASS" : "FAIL") << "\n\n";

        if (!bundle.ctdata_verified) {
            return 4;
        }
    }

    cout << "Phase 1 artifacts loaded from: build/" << kBinaryDir << '\n';
    cout << "Phase 3 bundles written to: build/Output" << endl;
    return 0;
}
