#ifndef HYBRID_PKI_BRIDGE_HPP
#define HYBRID_PKI_BRIDGE_HPP

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// Person 1 Cryptographic Engine
#include "crypto_api.hpp"

// Person 2 PKI & Certificate Management
#include "person2_pki/CertificateIdentityMapper.h"
#include "person2_pki/CertificateValidator.h"
#include "person2_pki/PKIManager.h"
#include "person2_pki/RevocationManager.h"

namespace hybrid_pki_scada {

/**
 * @brief Represents the cryptographic binding between a SCADA device identity,
 * its Person 2 RSA X.509 certificate, and its Person 1 GGH lattice public key.
 *
 * Security Rationale:
 * In a hybrid post-quantum SCADA scheme, an X.509 certificate only authenticates
 * the classical RSA-4096 public key. Without an explicit, verified binding between
 * the Subject Identity and the GGH lattice public key, an active adversary could
 * carry out a GGH public key substitution attack while reusing a valid RSA certificate.
 *
 * This binding guarantees:
 * 1. The X.509 certificate is valid and signed by the trusted Root CA.
 * 2. The X.509 certificate is not revoked in the CRL / revocation database.
 * 3. The X.509 certificate fingerprint maps uniquely to the authorized Device ID.
 * 4. The GGH lattice public key fingerprint strictly matches the device's registered GGH key.
 * 5. Both RSA and GGH signatures in the hybrid command envelope are valid.
 */
struct HybridDeviceBinding {
    std::string device_id;             // SCADA identifier, e.g. "SCADA-PLC-01"
    std::string certificate_path;      // Path to device's X.509 certificate PEM
    std::string certificate_serial;    // Normalized hex serial number
    std::string x509_fingerprint;      // Normalized SHA-256 fingerprint of X.509 cert
    std::string ggh_fingerprint;       // Fingerprint of the GGH lattice public key
    std::string binding_id;            // Unique binding identifier
    bool is_active{true};
};

/**
 * @brief Granular diagnostic validation and verification report.
 */
struct HybridValidationReport {
    bool x509_valid{false};             // Step 1: X.509 certificate signature chain valid
    bool revocation_checked{false};     // Step 2: Checked against revocation blacklist
    bool not_revoked{false};            // Step 2: Certificate serial is not revoked
    bool identity_mapped{false};        // Step 3: Certificate mapped to authorized device
    bool ggh_binding_valid{false};      // Step 4: GGH key fingerprint matches registered binding
    bool rsa_signature_valid{false};    // Step 5: Person 1 RSA-4096-PSS signature verified
    bool ggh_signature_valid{false};    // Step 5: Person 1 GGH-200 lattice signature verified
    bool overall_valid{false};          // True ONLY if all steps 1-5 succeed
    std::string error_message;          // Human-readable diagnostic error if invalid
    std::string authenticated_device;   // Confirmed authenticated device identity
    hybrid_pki::OperationMeasurements measurements; // Nanosecond benchmarks
};

/**
 * @brief Integration service bridging Person 1 (Cryptography & Signing) and Person 2 (PKI & CA).
 */
class HybridPKIService {
public:
    HybridPKIService();
    ~HybridPKIService() = default;

    /**
     * @brief Configure the PKI trust root and revocation store using Person 2's components.
     * @param trusted_ca_bundle Path to trusted Root CA PEM bundle
     * @param revoked_serials_file Path to revoked serials list file
     */
    bool configureTrustStore(const std::string& trusted_ca_bundle,
                             const std::string& revoked_serials_file,
                             std::string& error);

    /**
     * @brief Register and bind a SCADA device with its Person 2 X.509 certificate
     * and Person 1 GGH public key.
     * Validates that the certificate is currently valid under the trust store before binding.
     * @param device_id Unique SCADA device ID (e.g. "SCADA-PLC-01")
     * @param certificate_path Path to the device's PEM certificate
     * @param ggh_key_pair GGH key pair containing the lattice public key
     * @param error Output error string on failure
     * @return true if successfully bound, false otherwise
     */
    bool registerAndBindDevice(const std::string& device_id,
                               const std::string& certificate_path,
                               const hybrid_pki::GGHKeyPair& ggh_key_pair,
                               std::string& error);

    /**
     * @brief Revoke a device certificate in Person 2's revocation manager.
     * @param serial_hex Hex serial number of the certificate to revoke
     * @param error Output error description
     */
    bool revokeDeviceCertificate(const std::string& serial_hex, std::string& error);

    /**
     * @brief Revoke all certificates bound to a specific device.
     */
    bool revokeDevice(const std::string& device_id, std::string& error);

    /**
     * @brief Perform end-to-end cryptographic and PKI verification:
     * 1. Validate X.509 certificate chain against trusted Root CA.
     * 2. Verify certificate serial is not revoked.
     * 3. Map certificate fingerprint to registered device identity.
     * 4. Verify that the presented GGH public key matches the bound GGH key for that device.
     * 5. Verify the Person 1 hybrid signature (both RSA-4096-PSS and GGH lattice).
     */
    HybridValidationReport validateAndVerifyCommand(
        const hybrid_pki::HybridSignedCommand& command,
        const std::string& certificate_path,
        const hybrid_pki::RSAKeyPair& rsa_key_pair,
        const hybrid_pki::GGHKeyPair& ggh_key_pair);

    /**
     * @brief Retrieve active binding for a device.
     */
    bool getBinding(const std::string& device_id, HybridDeviceBinding& out_binding) const;

    /**
     * @brief Read normalized serial number from a PEM certificate file.
     */
    static bool extractCertificateSerial(const std::string& certificate_path,
                                         std::string& out_serial,
                                         std::string& error);

    /**
     * @brief Compute fingerprint for a GGH public key.
     */
    static std::string computeGGHFingerprint(const hybrid_pki::GGHPublicKey& pub_key);

private:
    std::string m_trusted_ca_bundle;
    std::string m_revoked_serials_file;
    CertificateValidator m_validator;
    CertificateIdentityMapper m_mapper;
    RevocationManager m_revocation;
    std::unordered_map<std::string, HybridDeviceBinding> m_bindings_by_device;
    std::unordered_map<std::string, std::string> m_cert_fp_to_device;
};

} // namespace hybrid_pki_scada

#endif // HYBRID_PKI_BRIDGE_HPP
