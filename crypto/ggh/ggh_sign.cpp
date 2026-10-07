#include "crypto_api.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

namespace hybrid_pki {

vector<int64_t> gghHashTarget(const string& message, size_t dimension);
vector<int64_t> gghRoundToLattice(const vector<int64_t>& target,
                                  const vector<int64_t>& short_basis,
                                  size_t dimension);

GGHSignature signGGH(const string& message, const GGHKeyPair& key_pair) {
    if (!key_pair.private_key || key_pair.private_key->dimension == 0) {
        throw invalid_argument("GGH private key is unavailable");
    }
    const auto target = gghHashTarget(message, key_pair.private_key->dimension);
    return {gghRoundToLattice(target, key_pair.private_key->short_basis,
                              key_pair.private_key->dimension)};
}

}  // namespace hybrid_pki
