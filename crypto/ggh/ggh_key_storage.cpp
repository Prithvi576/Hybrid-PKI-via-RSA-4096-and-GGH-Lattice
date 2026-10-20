
#include "crypto_api.hpp"

#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace hybrid_pki {
namespace {

constexpr const char* kFormat = "GGH_PUBLIC_KEY_V1";
constexpr std::size_t kMaxDimension = 256;

std::string calculateFingerprint(const std::vector<std::int64_t>& basis) {
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digestLength = 0;

    if (EVP_Digest(
            basis.data(),
            basis.size() * sizeof(std::int64_t),
            digest,
            &digestLength,
            EVP_sha256(),
            nullptr) != 1) {
        throw std::runtime_error("GGH fingerprint calculation failed");
    }

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;

    for (unsigned int i = 0; i < 10 && i < digestLength; ++i) {
        result += hex[digest[i] >> 4];
        result += hex[digest[i] & 0x0f];
    }

    return result;
}

bool validPublicKey(const GGHPublicKey& key) {
    if (key.dimension == 0 || key.dimension > kMaxDimension) {
        return false;
    }

    if (key.dimension >
        std::numeric_limits<std::size_t>::max() / key.dimension) {
        return false;
    }

    if (key.bad_basis.size() != key.dimension * key.dimension) {
        return false;
    }

    return std::isfinite(key.maximum_distance_squared) &&
           key.maximum_distance_squared >= 0.0L;
}

} // namespace

bool saveGGHPublicKey(
    const std::string& file_path,
    const GGHKeyPair& key_pair) {

    if (file_path.empty() ||
        !key_pair.has_public_key() ||
        !validPublicKey(*key_pair.public_key)) {
        return false;
    }

    std::ofstream file(file_path, std::ios::out | std::ios::trunc);

    if (!file.is_open()) {
        return false;
    }

    const auto& key = *key_pair.public_key;

    file << kFormat << '\n';
    file << key.dimension << '\n';
    file << std::setprecision(
        std::numeric_limits<long double>::max_digits10)
         << key.maximum_distance_squared << '\n';

    for (std::size_t i = 0; i < key.bad_basis.size(); ++i) {
        file << key.bad_basis[i]
             << ((i + 1) % key.dimension == 0 ? '\n' : ' ');
    }

    file.flush();

    if (!file.good()) {
        file.close();
        return false;
    }

    file.close();
    return !file.fail();
}

GGHKeyPair loadGGHPublicKey(const std::string& file_path) {
    if (file_path.empty()) {
        throw std::invalid_argument("GGH public-key path is empty");
    }

    std::ifstream file(file_path);

    if (!file.is_open()) {
        throw std::runtime_error("Cannot open GGH public-key file");
    }

    std::string format;
    if (!(file >> format) || format != kFormat) {
        throw std::runtime_error("Invalid GGH public-key file format");
    }

    std::size_t dimension = 0;
    long double threshold = 0.0L;

    if (!(file >> dimension) ||
        dimension == 0 ||
        dimension > kMaxDimension) {
        throw std::runtime_error("Invalid GGH public-key dimension");
    }

    if (dimension >
        std::numeric_limits<std::size_t>::max() / dimension) {
        throw std::runtime_error("GGH public-key dimension overflow");
    }

    if (!(file >> threshold) ||
        !std::isfinite(threshold) ||
        threshold < 0.0L) {
        throw std::runtime_error("Invalid GGH verification threshold");
    }

    auto public_key = std::make_shared<GGHPublicKey>();
    public_key->dimension = dimension;
    public_key->maximum_distance_squared = threshold;
    public_key->bad_basis.resize(dimension * dimension);

    for (auto& value : public_key->bad_basis) {
        if (!(file >> value)) {
            throw std::runtime_error("Incomplete GGH public basis");
        }
    }

    // Reject unexpected trailing data.
    file >> std::ws;
    if (!file.eof()) {
        throw std::runtime_error("Unexpected trailing GGH key data");
    }

    if (!validPublicKey(*public_key)) {
        throw std::runtime_error("Invalid GGH public key");
    }

    GGHKeyPair result;
    result.private_key.reset();
    result.public_key = std::move(public_key);
    result.public_fingerprint =
        calculateFingerprint(result.public_key->bad_basis);

    return result;
}

} // namespace hybrid_pki
