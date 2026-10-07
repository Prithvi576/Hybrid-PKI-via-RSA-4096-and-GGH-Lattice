#include "crypto_api.hpp"

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace hybrid_pki {

vector<int64_t> gghHashTarget(const string& message, size_t dimension);
bool gghIsPublicLatticePoint(const vector<int64_t>& point,
                             const vector<int64_t>& bad_basis,
                             size_t dimension) noexcept;
long double gghDistanceSquared(const vector<int64_t>& left,
                               const vector<int64_t>& right) noexcept;

bool verifyGGH(const string& message, const GGHSignature& signature,
               const GGHKeyPair& key_pair) noexcept {
    try {
        if (message.empty() || !key_pair.public_key ||
            signature.lattice_point.size() != key_pair.public_key->dimension) {
            return false;
        }
        const auto target = gghHashTarget(message, key_pair.public_key->dimension);
        return gghIsPublicLatticePoint(signature.lattice_point, key_pair.public_key->bad_basis,
                                       key_pair.public_key->dimension) &&
               gghDistanceSquared(signature.lattice_point, target) <=
                   key_pair.public_key->maximum_distance_squared;
    } catch (...) {
        return false;
    }
}

}  // namespace hybrid_pki
