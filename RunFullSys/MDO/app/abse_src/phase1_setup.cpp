#include "phase1_setup.h"

#include <openfhe/core/lattice/trapdoorparameters.h>
#include <openfhe/core/utils/serial.h>

#include <fstream>
#include <stdexcept>
#include <string>

namespace {

std::string JoinPath(const std::string& directory, const std::string& filename) {
    if (directory.empty() || directory == ".") {
        return filename;
    }
    if (directory.back() == '/') {
        return directory + filename;
    }
    return directory + "/" + filename;
}

void RestoreMatrixAllocator(const std::shared_ptr<ElementParams>& elem_params, TrapdoorMatrix& matrix) {
    matrix.SetAllocator(TrapdoorElement::Allocator(elem_params, Format::EVALUATION));
}

void RestoreTrapdoorAllocators(const std::shared_ptr<ElementParams>& elem_params, TrapdoorPair& trapdoor) {
    trapdoor.m_r.SetAllocator(TrapdoorElement::Allocator(elem_params, Format::EVALUATION));
    trapdoor.m_e.SetAllocator(TrapdoorElement::Allocator(elem_params, Format::EVALUATION));
}

bool WriteParamsFile(const SystemParams& params, const std::string& path) {
    std::ofstream out(path);
    if (!out.is_open()) {
        return false;
    }

    out << "ring_dim=" << params.ring_dim << '\n';
    out << "modulus=" << params.modulus << '\n';
    out << "trapdoor_stddev=" << params.trapdoor_stddev << '\n';
    out << "gadget_base=" << params.gadget_base << '\n';
    out << "balanced=" << (params.balanced ? 1 : 0) << '\n';
    out << "trapdoor_k=" << params.trapdoor_k << '\n';
    return true;
}

bool ReadParamsFile(SystemParams& params, const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(in, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        const auto key = line.substr(0, pos);
        const auto value = line.substr(pos + 1);

        if (key == "ring_dim") {
            params.ring_dim = static_cast<uint32_t>(std::stoul(value));
        } else if (key == "modulus") {
            params.modulus = std::stoull(value);
        } else if (key == "trapdoor_stddev") {
            params.trapdoor_stddev = std::stod(value);
        } else if (key == "gadget_base") {
            params.gadget_base = std::stoll(value);
        } else if (key == "balanced") {
            params.balanced = (std::stoi(value) != 0);
        } else if (key == "trapdoor_k") {
            params.trapdoor_k = static_cast<size_t>(std::stoull(value));
        }
    }

    return params.ring_dim != 0 && params.modulus != 0 && params.gadget_base > 1;
}

}  // namespace

void InitSystemParams(SystemParams& params, uint32_t ring_dim, uint64_t modulus, double trapdoor_stddev,
                      int64_t gadget_base, bool balanced) {
    if (ring_dim == 0 || modulus == 0 || trapdoor_stddev <= 0.0 || gadget_base <= 1) {
        throw std::invalid_argument("invalid system parameters");
    }

    params.ring_dim = ring_dim;
    params.modulus = modulus;
    params.trapdoor_stddev = trapdoor_stddev;
    params.gadget_base = gadget_base;
    params.balanced = balanced;
    params.trapdoor_k = 0;
}

std::shared_ptr<ElementParams> BuildElementParams(const SystemParams& params) {
    return std::make_shared<ElementParams>(2 * params.ring_dim, lbcrypto::BigInteger(std::to_string(params.modulus)));
}

void Setup(SystemParams& params, PK& pk, MSK& msk) {
    auto elem_params = BuildElementParams(params);
    const auto setup_pair = lbcrypto::RLWETrapdoorUtility<TrapdoorElement>::TrapdoorGen(
        elem_params, params.trapdoor_stddev, params.gadget_base, params.balanced);

    pk.A = setup_pair.first;
    msk.trapdoor = setup_pair.second;
    params.trapdoor_k = pk.A.GetCols() - 2;

    RestoreMatrixAllocator(elem_params, pk.A);
    RestoreTrapdoorAllocators(elem_params, msk.trapdoor);
}

TrapdoorElement MakeDeterministicSyndrome(const SystemParams& params, const std::string& label) {
    auto elem_params = BuildElementParams(params);
    TrapdoorElement syndrome(elem_params, Format::COEFFICIENT, true);

    uint64_t label_sum = 0;
    for (unsigned char ch : label) {
        label_sum = (label_sum * 257 + ch) % 0xFFFFFFFFull;
    }

    for (uint32_t i = 0; i < params.ring_dim; ++i) {
        const uint64_t coeff = (label_sum + 17ull * (i + 1)) % params.modulus;
        syndrome[i] = TrapdoorElement::Integer(coeff);
    }

    syndrome.SetFormat(Format::EVALUATION);
    return syndrome;
}

TrapdoorMatrix SamplePreimage(const SystemParams& params, const PK& pk, const MSK& msk,
                              const TrapdoorElement& syndrome) {
    auto elem_params = BuildElementParams(params);
    TrapdoorElement::DggType dgg(params.trapdoor_stddev);
    lbcrypto::RLWETrapdoorParams<TrapdoorElement> trapdoor_params(elem_params, dgg, params.trapdoor_stddev,
                                                                  params.gadget_base, params.balanced);

    return lbcrypto::RLWETrapdoorUtility<TrapdoorElement>::GaussSamp(
        params.ring_dim, trapdoor_params.GetK(), pk.A, msk.trapdoor, syndrome, dgg,
        trapdoor_params.GetDGGLargeSigma(), params.gadget_base);
}

bool VerifyPreimage(const PK& pk, const TrapdoorElement& syndrome, const TrapdoorMatrix& preimage) {
    if (pk.A.GetCols() != preimage.GetRows() || preimage.GetCols() != 1 || pk.A.GetRows() != 1) {
        return false;
    }

    const TrapdoorMatrix result = pk.A.Mult(preimage);
    if (result.GetRows() != 1 || result.GetCols() != 1) {
        return false;
    }

    TrapdoorElement lhs = result(0, 0);
    TrapdoorElement rhs = syndrome;
    lhs.SetFormat(Format::COEFFICIENT);
    rhs.SetFormat(Format::COEFFICIENT);
    return lhs == rhs;
}

bool SavePhase1Artifacts(const SystemParams& params, const PK& pk, const MSK& msk, const std::string& directory) {
    const auto params_path = JoinPath(directory, "phase1_params.txt");
    const auto pk_path = JoinPath(directory, "phase1_public_key.bin");
    const auto msk_path = JoinPath(directory, "phase1_trapdoor.bin");

    return WriteParamsFile(params, params_path) &&
           lbcrypto::Serial::SerializeToFile(pk_path, pk.A, lbcrypto::SerType::BINARY) &&
           lbcrypto::Serial::SerializeToFile(msk_path, msk.trapdoor, lbcrypto::SerType::BINARY);
}

bool LoadPhase1Artifacts(SystemParams& params, PK& pk, MSK& msk, const std::string& directory) {
    const auto params_path = JoinPath(directory, "phase1_params.txt");
    const auto pk_path = JoinPath(directory, "phase1_public_key.bin");
    const auto msk_path = JoinPath(directory, "phase1_trapdoor.bin");

    if (!ReadParamsFile(params, params_path)) {
        return false;
    }
    if (!lbcrypto::Serial::DeserializeFromFile(pk_path, pk.A, lbcrypto::SerType::BINARY)) {
        return false;
    }
    if (!lbcrypto::Serial::DeserializeFromFile(msk_path, msk.trapdoor, lbcrypto::SerType::BINARY)) {
        return false;
    }

    auto elem_params = BuildElementParams(params);
    RestoreMatrixAllocator(elem_params, pk.A);
    RestoreTrapdoorAllocators(elem_params, msk.trapdoor);
    return true;
}
