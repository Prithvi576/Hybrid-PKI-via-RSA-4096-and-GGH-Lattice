#include "crypto_api.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>

using namespace std;

namespace hybrid_pki {

namespace {
constexpr size_t kDimension = 16;

int64_t secureInteger(const int64_t minimum, const int64_t maximum) {
    const auto span = static_cast<uint64_t>(maximum - minimum + 1);
    const auto limit = numeric_limits<uint64_t>::max() -
                       (numeric_limits<uint64_t>::max() % span);
    uint64_t value = 0;
    do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
            throw runtime_error("OpenSSL secure random generation failed for GGH");
        }
    } while (value >= limit);
    return minimum + static_cast<int64_t>(value % span);
}

vector<int64_t> multiply(const vector<int64_t>& left,
                         const vector<int64_t>& right) {
    vector<int64_t> result(kDimension * kDimension, 0);
    for (size_t row = 0; row < kDimension; ++row) {
        for (size_t column = 0; column < kDimension; ++column) {
            long double value = 0.0L;
            for (size_t index = 0; index < kDimension; ++index) {
                value += static_cast<long double>(left[row * kDimension + index]) *
                         static_cast<long double>(right[index * kDimension + column]);
            }
            if (value > numeric_limits<int64_t>::max() ||
                value < numeric_limits<int64_t>::min()) {
                throw overflow_error("GGH public-basis generation overflow");
            }
            result[row * kDimension + column] = static_cast<int64_t>(llround(value));
        }
    }
    return result;
}
}  // namespace

GGHKeyPair generateGGHKeyPair() {
    auto private_key = make_shared<GGHPrivateKey>();
    private_key->dimension = kDimension;
    private_key->short_basis.assign(kDimension * kDimension, 0);
    for (size_t row = 0; row < kDimension; ++row) {
        for (size_t column = 0; column < kDimension; ++column) {
            private_key->short_basis[row * kDimension + column] =
                row == column ? 59 : secureInteger(-3, 3);
        }
    }

    vector<int64_t> unimodular(kDimension * kDimension, 0);
    for (size_t index = 0; index < kDimension; ++index) {
        unimodular[index * kDimension + index] = 1;
    }
    // Elementary row additions preserve determinant ±1 and therefore the lattice.
    for (size_t operation = 0; operation < kDimension * 8; ++operation) {
        const auto destination = static_cast<size_t>(secureInteger(0, kDimension - 1));
        size_t source = static_cast<size_t>(secureInteger(0, kDimension - 1));
        while (source == destination) {
            source = static_cast<size_t>(secureInteger(0, kDimension - 1));
        }
        const auto multiplier = secureInteger(-2, 2);
        if (multiplier == 0) {
            continue;
        }
        for (size_t column = 0; column < kDimension; ++column) {
            const long double value =
                static_cast<long double>(unimodular[destination * kDimension + column]) +
                static_cast<long double>(multiplier) *
                    static_cast<long double>(unimodular[source * kDimension + column]);
            if (value > numeric_limits<int64_t>::max() ||
                value < numeric_limits<int64_t>::min()) {
                throw overflow_error("GGH unimodular transform overflow");
            }
            unimodular[destination * kDimension + column] = static_cast<int64_t>(llround(value));
        }
    }

    auto public_key = make_shared<GGHPublicKey>();
    public_key->dimension = kDimension;
    public_key->bad_basis = multiply(unimodular, private_key->short_basis);
    public_key->maximum_distance_squared = 0.0L;
    for (size_t column = 0; column < kDimension; ++column) {
        long double coordinate_bound = 0.0L;
        for (size_t row = 0; row < kDimension; ++row) {
            coordinate_bound += fabs(static_cast<long double>(
                private_key->short_basis[row * kDimension + column]));
        }
        public_key->maximum_distance_squared +=
            (coordinate_bound * 0.5L) * (coordinate_bound * 0.5L);
    }
    public_key->maximum_distance_squared += 1e-6L;

    array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    if (EVP_Digest(public_key->bad_basis.data(),
                   public_key->bad_basis.size() * sizeof(int64_t), digest.data(), &digest_length,
                   EVP_sha256(), nullptr) != 1) {
        throw runtime_error("GGH public-key fingerprinting failed");
    }
    ostringstream fingerprint;
    fingerprint << hex << setfill('0');
    for (unsigned int index = 0; index < 10 && index < digest_length; ++index) {
        fingerprint << setw(2) << static_cast<unsigned int>(digest[index]);
    }

    GGHKeyPair result;
    result.private_key = move(private_key);
    result.public_key = move(public_key);
    result.public_fingerprint = fingerprint.str();
    return result;
}

}  // namespace hybrid_pki
