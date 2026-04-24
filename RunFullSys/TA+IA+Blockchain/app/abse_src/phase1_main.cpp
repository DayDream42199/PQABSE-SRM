#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "phase1_setup.h"

using namespace std;

namespace {

const string kOutputRoot = "Output";
const string kReadableDir = kOutputRoot + "/Readable";
const string kBinaryDir = kOutputRoot + "/Binary";

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

bool WriteReadablePhase1Files(const SystemParams& params, const PK& pk, const MSK& msk) {
    ofstream pk_out(kReadableDir + "/phase1_public_key_readable.txt");
    ofstream msk_out(kReadableDir + "/phase1_trapdoor_readable.txt");
    ofstream summary(kReadableDir + "/phase1_summary.txt");

    if (!pk_out.is_open() || !msk_out.is_open() || !summary.is_open()) {
        return false;
    }

    summary << "ring_dim=" << params.ring_dim << '\n';
    summary << "modulus=" << params.modulus << '\n';
    summary << "trapdoor_stddev=" << params.trapdoor_stddev << '\n';
    summary << "gadget_base=" << params.gadget_base << '\n';
    summary << "balanced=" << (params.balanced ? 1 : 0) << '\n';
    summary << "trapdoor_k=" << params.trapdoor_k << '\n';
    summary << "A_dims=" << pk.A.GetRows() << "x" << pk.A.GetCols() << '\n';
    summary << "trapdoor_r_dims=" << msk.trapdoor.m_r.GetRows() << "x" << msk.trapdoor.m_r.GetCols() << '\n';
    summary << "trapdoor_e_dims=" << msk.trapdoor.m_e.GetRows() << "x" << msk.trapdoor.m_e.GetCols() << '\n';

    pk_out << "A_dims=" << pk.A.GetRows() << "x" << pk.A.GetCols() << "\n";
    pk_out << FormatMatrixReadable(pk.A) << "\n";

    msk_out << "R_dims=" << msk.trapdoor.m_r.GetRows() << "x" << msk.trapdoor.m_r.GetCols() << "\n";
    msk_out << FormatMatrixReadable(msk.trapdoor.m_r) << "\n\n";
    msk_out << "E_dims=" << msk.trapdoor.m_e.GetRows() << "x" << msk.trapdoor.m_e.GetCols() << "\n";
    msk_out << FormatMatrixReadable(msk.trapdoor.m_e) << "\n";

    return true;
}

}  // namespace

int main() {
    SystemParams params;
    PK pk;
    MSK msk;

    cout << "[*] Initializing OpenFHE RLWE trapdoor parameters..." << endl;
    InitSystemParams(params, 256, 12289, 3.2, 2, false);

    cout << "[*] Running Phase 1 setup..." << endl;
    Setup(params, pk, msk);

    std::filesystem::create_directories(kReadableDir);
    std::filesystem::create_directories(kBinaryDir);

    cout << "[*] Saving Phase 1 artifacts..." << endl;
    if (!SavePhase1Artifacts(params, pk, msk, kBinaryDir)) {
        cerr << "Failed to save Phase 1 binary artifacts" << endl;
        return 1;
    }
    if (!WriteReadablePhase1Files(params, pk, msk)) {
        cerr << "Failed to save Phase 1 readable artifacts" << endl;
        return 1;
    }

    cout << "--- Phase 1 Complete ---" << endl;
    cout << "Public matrix A dimensions: " << pk.A.GetRows() << " x " << pk.A.GetCols() << endl;
    cout << "Trapdoor dimensions (R/E): " << msk.trapdoor.m_r.GetRows() << " x " << msk.trapdoor.m_r.GetCols() << endl;
    cout << "Trapdoor k: " << params.trapdoor_k << endl;
    cout << "Artifacts written to: build/Output" << endl;

    return 0;
}
