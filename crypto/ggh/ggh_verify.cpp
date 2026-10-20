#include "../crypto_api.hpp"
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace hybrid_pki {

vector<int64_t> gghHashTarget(const string& message, size_t dimension);

bool gghIsPublicLatticePoint(
    const vector<int64_t>& point,
    const vector<int64_t>& bad_basis,
    size_t dimension) noexcept;

long double gghDistanceSquared(
    const vector<int64_t>& left,
    const vector<int64_t>& right) noexcept;


// Verify using ONLY the public key.
bool verifyGGH(
    const string& message,
    const GGHSignature& signature,
    const GGHPublicKey& public_key) noexcept {
    try {
        if (message.empty() ||
            public_key.dimension == 0 ||
            signature.lattice_point.size() != public_key.dimension ||
            public_key.bad_basis.size() !=
                public_key.dimension * public_key.dimension ||
            !std::isfinite(public_key.maximum_distance_squared) ||
            public_key.maximum_distance_squared < 0.0L) {
            return false;
        }

        const auto target =
            gghHashTarget(message, public_key.dimension);

        return gghIsPublicLatticePoint(
                   signature.lattice_point,
                   public_key.bad_basis,
                   public_key.dimension) &&
               gghDistanceSquared(
                   signature.lattice_point, target) <=
                   public_key.maximum_distance_squared;
    } catch (...) {
        return false;
    }
}


// Backward-compatible wrapper for existing callers.
bool verifyGGH(
    const string& message,
    const GGHSignature& signature,
    const GGHKeyPair& key_pair) noexcept {
    if (!key_pair.public_key) {
        return false;
    }

    return verifyGGH(message, signature, *key_pair.public_key);
}

}  // namespace hybrid_pki
