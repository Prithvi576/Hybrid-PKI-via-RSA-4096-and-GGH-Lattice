#include "crypto_api.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace std;

namespace hybrid_pki {

namespace {
constexpr size_t kEducationalDimension = 16;
}  // namespace

bool GGHKeyPair::has_private_key() const noexcept { return static_cast<bool>(private_key); }
bool GGHKeyPair::has_public_key() const noexcept { return static_cast<bool>(public_key); }

vector<long double> gghMatrixInverse(const vector<int64_t>& matrix, const size_t dimension) {
    if (matrix.size() != dimension * dimension || dimension == 0) {
        throw invalid_argument("invalid GGH basis dimensions");
    }
    const size_t augmented_width = dimension * 2;
    vector<long double> augmented(dimension * augmented_width, 0.0L);
    for (size_t row = 0; row < dimension; ++row) {
        for (size_t column = 0; column < dimension; ++column) {
            augmented[row * augmented_width + column] =
                static_cast<long double>(matrix[row * dimension + column]);
        }
        augmented[row * augmented_width + dimension + row] = 1.0L;
    }

    for (size_t pivot = 0; pivot < dimension; ++pivot) {
        size_t selected = pivot;
        for (size_t candidate = pivot + 1; candidate < dimension; ++candidate) {
            if (fabs(augmented[candidate * augmented_width + pivot]) >
                fabs(augmented[selected * augmented_width + pivot])) {
                selected = candidate;
            }
        }
        if (fabs(augmented[selected * augmented_width + pivot]) < 1e-18L) {
            throw invalid_argument("GGH basis is singular");
        }
        if (selected != pivot) {
            for (size_t column = 0; column < augmented_width; ++column) {
                swap(augmented[pivot * augmented_width + column],
                     augmented[selected * augmented_width + column]);
            }
        }
        const long double divisor = augmented[pivot * augmented_width + pivot];
        for (size_t column = 0; column < augmented_width; ++column) {
            augmented[pivot * augmented_width + column] /= divisor;
        }
        for (size_t row = 0; row < dimension; ++row) {
            if (row == pivot) {
                continue;
            }
            const long double factor = augmented[row * augmented_width + pivot];
            for (size_t column = 0; column < augmented_width; ++column) {
                augmented[row * augmented_width + column] -=
                    factor * augmented[pivot * augmented_width + column];
            }
        }
    }

    vector<long double> inverse(dimension * dimension, 0.0L);
    for (size_t row = 0; row < dimension; ++row) {
        for (size_t column = 0; column < dimension; ++column) {
            inverse[row * dimension + column] =
                augmented[row * augmented_width + dimension + column];
        }
    }
    return inverse;
}

vector<int64_t> gghHashTarget(const string& message, const size_t dimension) {
    if (message.empty() || dimension != kEducationalDimension) {
        throw invalid_argument("GGH requires a non-empty message and supported dimension");
    }
    array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    if (EVP_Digest(message.data(), message.size(), digest.data(), &digest_length, EVP_sha256(),
                   nullptr) != 1 ||
        digest_length != 32) {
        throw runtime_error("SHA-256 target mapping failed for GGH");
    }
    vector<int64_t> target(dimension, 0);
    for (size_t index = 0; index < dimension; ++index) {
        const uint16_t word = static_cast<uint16_t>(digest[index * 2] << 8U) |
                              static_cast<uint16_t>(digest[index * 2 + 1]);
        target[index] = static_cast<int64_t>(word) - 32768;
    }
    return target;
}

vector<int64_t> gghRoundToLattice(const vector<int64_t>& target,
                                  const vector<int64_t>& short_basis,
                                  const size_t dimension) {
    const auto inverse = gghMatrixInverse(short_basis, dimension);
    vector<long double> coordinates(dimension, 0.0L);
    for (size_t column = 0; column < dimension; ++column) {
        for (size_t row = 0; row < dimension; ++row) {
            coordinates[column] += static_cast<long double>(target[row]) *
                                   inverse[row * dimension + column];
        }
        coordinates[column] = round(coordinates[column]);
    }
    vector<int64_t> signature(dimension, 0);
    for (size_t column = 0; column < dimension; ++column) {
        long double value = 0.0L;
        for (size_t row = 0; row < dimension; ++row) {
            value += coordinates[row] *
                     static_cast<long double>(short_basis[row * dimension + column]);
        }
        if (value > static_cast<long double>(numeric_limits<int64_t>::max()) ||
            value < static_cast<long double>(numeric_limits<int64_t>::min())) {
            throw overflow_error("GGH signature coordinate overflow");
        }
        signature[column] = static_cast<int64_t>(llround(value));
    }
    return signature;
}

bool gghIsPublicLatticePoint(const vector<int64_t>& point,
                             const vector<int64_t>& bad_basis,
                             const size_t dimension) noexcept {
    try {
        if (point.size() != dimension || bad_basis.size() != dimension * dimension) {
            return false;
        }
        const auto inverse = gghMatrixInverse(bad_basis, dimension);
        for (size_t column = 0; column < dimension; ++column) {
            long double coordinate = 0.0L;
            for (size_t row = 0; row < dimension; ++row) {
                coordinate += static_cast<long double>(point[row]) *
                              inverse[row * dimension + column];
            }
            if (fabs(coordinate - round(coordinate)) > 1e-7L) {
                return false;
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

long double gghDistanceSquared(const vector<int64_t>& left,
                               const vector<int64_t>& right) noexcept {
    if (left.size() != right.size()) {
        return numeric_limits<long double>::infinity();
    }
    long double result = 0.0L;
    for (size_t index = 0; index < left.size(); ++index) {
        const long double difference = static_cast<long double>(left[index]) -
                                       static_cast<long double>(right[index]);
        result += difference * difference;
    }
    return result;
}

size_t gghSignatureSize(const GGHSignature& signature) noexcept {
    return signature.lattice_point.size() * sizeof(int64_t);
}

string gghConfiguration() {
    return "Educational GGH hash-and-sign | n=16 | SHA-256 target | Babai round-off CVP";
}

}  // namespace hybrid_pki
