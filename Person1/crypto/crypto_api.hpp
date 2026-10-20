#ifndef HYBRID_PKI_CRYPTO_API_HPP
#define HYBRID_PKI_CRYPTO_API_HPP

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hybrid_pki {

// ---------------------------------------------------------------------------
// RSA-4096
// ---------------------------------------------------------------------------

struct RSAKeyPair {
    std::shared_ptr<void> private_handle;
    std::shared_ptr<void> public_handle;
    std::string           public_fingerprint;

    bool has_private_key() const noexcept;
    bool has_public_key()  const noexcept;
};

RSAKeyPair                generateRSAKeyPair();
std::vector<unsigned char> signRSA(const std::string& message, const RSAKeyPair& key_pair);
bool                       verifyRSA(const std::string& message,
                                     const std::vector<unsigned char>& signature,
                                     const RSAKeyPair& key_pair) noexcept;

// ---------------------------------------------------------------------------
// GGH lattice-based signature (educational reference)
// ---------------------------------------------------------------------------

struct GGHPrivateKey {
    std::size_t              dimension{};
    std::vector<std::int64_t> short_basis;
};

struct GGHPublicKey {
    std::size_t              dimension{};
    std::vector<std::int64_t> bad_basis;
    long double              maximum_distance_squared{};
};

struct GGHSignature {
    std::vector<std::int64_t> lattice_point;
};

struct GGHKeyPair {
    std::shared_ptr<GGHPrivateKey> private_key;
    std::shared_ptr<GGHPublicKey>  public_key;
    std::string                    public_fingerprint;

    bool has_private_key() const noexcept;
    bool has_public_key()  const noexcept;
};

GGHKeyPair   generateGGHKeyPair();
GGHSignature signGGH(const std::string& message, const GGHKeyPair& key_pair);
bool         verifyGGH(const std::string& message, const GGHSignature& signature,
                        const GGHKeyPair& key_pair) noexcept;
std::size_t  gghSignatureSize(const GGHSignature& signature) noexcept;
std::string  gghConfiguration();

// ---------------------------------------------------------------------------
// Hybrid signing (RSA-4096 + GGH)
// ---------------------------------------------------------------------------

struct CommandEnvelope {
    std::string   command;
    std::string   timestamp_utc;
    std::uint64_t sequence{};
};

struct HybridSignedCommand {
    CommandEnvelope              envelope;
    std::vector<unsigned char>   rsa_signature;
    GGHSignature                 ggh_signature;
};

struct OperationMeasurements {
    std::chrono::nanoseconds rsa{};
    std::chrono::nanoseconds ggh{};
    std::chrono::nanoseconds hybrid{};
};

struct HybridSigningResult {
    HybridSignedCommand   signed_command;
    OperationMeasurements measurements;
};

struct HybridVerificationResult {
    bool                  rsa_valid{};
    bool                  ggh_valid{};
    bool                  overall_valid{};
    OperationMeasurements measurements;
};

std::string              canonicalize(const CommandEnvelope& envelope);
HybridSigningResult      hybridSign(const CommandEnvelope& envelope,
                                    const RSAKeyPair& rsa_key_pair,
                                    const GGHKeyPair& ggh_key_pair);
HybridVerificationResult hybridVerify(const HybridSignedCommand& command,
                                      const RSAKeyPair& rsa_key_pair,
                                      const GGHKeyPair& ggh_key_pair) noexcept;

}  // namespace hybrid_pki

#endif  // HYBRID_PKI_CRYPTO_API_HPP
