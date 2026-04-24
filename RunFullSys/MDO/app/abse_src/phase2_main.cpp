#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "phase2_keygen.h"

using namespace std;

namespace {

const string kOutputRoot = "Output";
const string kReadableDir = kOutputRoot + "/Readable";
const string kBinaryDir = kOutputRoot + "/Binary";

struct UserProfile {
    string label;
    string gid;
    vector<string> attributes;
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

string FormatMatrixReadable(const TrapdoorMatrix& matrix) {
    ostringstream out;
    out << "[\n";
    for (uint32_t row = 0; row < matrix.GetRows(); ++row) {
        out << "  [\n";
        for (uint32_t col = 0; col < matrix.GetCols(); ++col) {
            out << "    " << FormatElementReadable(matrix(row, col));
            if (col + 1 != matrix.GetCols()) {
                out << ',';
            }
            out << '\n';
        }
        out << "  ]";
        if (row + 1 != matrix.GetRows()) {
            out << ',';
        }
        out << '\n';
    }
    out << ']';
    return out.str();
}

void PrintSecretKeySummary(const UserProfile& profile, const UserSecretKey& user_sk) {
    cout << profile.label << " -> GID: " << user_sk.gid << '\n';
    cout << "Attributes:";
    for (const auto& attribute : user_sk.attributes) {
        cout << ' ' << attribute;
    }
    cout << '\n';
    cout << "Preimage dimensions: " << user_sk.preimage.GetRows() << " x " << user_sk.preimage.GetCols() << '\n';
}

bool WriteReadableUserKey(const SystemParams& params, const UserProfile& profile, const UserSecretKey& user_sk) {
    ofstream out(kReadableDir + "/" + profile.label + "_userkey_readable.txt");
    ofstream summary(kReadableDir + "/" + profile.label + "_userkey_summary.txt");
    if (!out.is_open() || !summary.is_open()) {
        return false;
    }

    summary << "label=" << profile.label << '\n';
    summary << "gid=" << user_sk.gid << '\n';
    summary << "attributes=";
    for (size_t i = 0; i < user_sk.attributes.size(); ++i) {
        if (i != 0) {
            summary << ',';
        }
        summary << user_sk.attributes[i];
    }
    summary << '\n';
    summary << "preimage_rows=" << user_sk.preimage.GetRows() << '\n';
    summary << "preimage_cols=" << user_sk.preimage.GetCols() << '\n';
    summary << "trapdoor_k=" << params.trapdoor_k << '\n';

    out << "label=" << profile.label << '\n';
    out << "gid=" << user_sk.gid << '\n';
    out << "attributes=";
    for (size_t i = 0; i < user_sk.attributes.size(); ++i) {
        if (i != 0) {
            out << ',';
        }
        out << user_sk.attributes[i];
    }
    out << "\n\n";
    out << "target_u:\n" << FormatElementReadable(user_sk.target_u) << "\n\n";
    out << "preimage:\n" << FormatMatrixReadable(user_sk.preimage) << "\n";
    return true;
}

bool GenerateAndWriteUserKey(const SystemParams& params, const PK& pk, const MSK& msk, const UserProfile& profile) {
    UserSecretKey user_sk;
    KeyGen(params, pk, msk, profile.gid, profile.attributes, user_sk);

    cout << "[*] Phase 2 ABSE key generation complete for " << profile.label << '\n';
    PrintSecretKeySummary(profile, user_sk);

    if (!VerifyUserSecretKey(pk, user_sk)) {
        cerr << "Verification failed for " << profile.label << '\n';
        return false;
    }

    if (!SaveUserSecretKey(params, user_sk, kBinaryDir + "/" + profile.label + "_userkey.bin")) {
        cerr << "Failed to save binary key for " << profile.label << '\n';
        return false;
    }

    if (!WriteReadableUserKey(params, profile, user_sk)) {
        cerr << "Failed to save readable key for " << profile.label << '\n';
        return false;
    }

    cout << "Verification: PASS\n\n";
    return true;
}

vector<UserProfile> BuildUserProfiles() {
    return {
        {"Peak", "01", {"Idiot", "CPE", "Black"}},
        {"Cheese", "02", {"CPE", "Smart", "White"}},
        {"Ing", "67", {"Asian", "Smart", "CPE"}},
        {"Minor", "69", {"Asian", "Smart", "CPE", "Roblox"}},
    };
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

    const auto users = BuildUserProfiles();
    for (const auto& user : users) {
        if (!GenerateAndWriteUserKey(params, pk, msk, user)) {
            return 2;
        }
    }

    cout << "Phase 1 artifacts loaded from: build/" << kBinaryDir << '\n';
    cout << "User keys written to: build/Output" << endl;
    return 0;
}
