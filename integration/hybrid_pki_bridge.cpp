#include "hybrid_pki_bridge.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace hybrid_pki_scada {

namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

std::string normalizeHex(std::string input) {
    std::string result;
    for (unsigned char c : input) {
        if (std::isxdigit(c)) {
            result.push_back(static_cast<char>(std::toupper(c)));
        }
    }
    const std::size_t first = result.find_first_not_of('0');
    if (first == std::string::npos) {
        return "0";
    }
    return result.substr(first);
}

std::string getOpenSSLError() {
    const unsigned long code = ERR_get_error();
    if (code == 0) {
        return "no additional OpenSSL error details";
    }
    char buffer[256] = {};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    return std::string(buffer);
}

} // namespace

HybridPKIService::HybridPKIService() = default;

bool HybridPKIService::configureTrustStore(const std::string& trusted_ca_bundle,
                                           const std::string& revoked_serials_file,
                                           std::string& error) {
    error.clear();
    if (trusted_ca_bundle.empty() || !std::filesystem::exists(trusted_ca_bundle)) {
        error = "Trusted CA bundle path is invalid or file does not exist: " + trusted_ca_bundle;
        return false;
    }

    m_trusted_ca_bundle = trusted_ca_bundle;
    m_revoked_serials_file = revoked_serials_file;

    // Ensure revocation file exists (create empty if missing)
    if (!m_revoked_serials_file.empty() && !std::filesystem::exists(m_revoked_serials_file)) {
        std::ofstream out(m_revoked_serials_file);
        if (!out.is_open()) {
            error = "Failed to create revocation list file: " + m_revoked_serials_file;
            return false;
        }
    }

    return true;
}

bool HybridPKIService::extractCertificateSerial(const std::string& certificate_path,
                                               std::string& out_serial,
                                               std::string& error) {
    out_serial.clear();
    error.clear();

    BioPtr bio(BIO_new_file(certificate_path.c_str(), "rb"), BIO_free);
    if (!bio) {
        error = "Cannot open certificate file: " + getOpenSSLError();
        return false;
    }

    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
    if (!cert) {
        error = "Cannot parse X.509 certificate: " + getOpenSSLError();
        return false;
    }

    BIGNUM* raw_bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert.get()), nullptr);
    BnPtr bn(raw_bn, BN_free);
    if (!bn) {
        error = "Cannot extract serial number BIGNUM: " + getOpenSSLError();
        return false;
    }

    char* hex = BN_bn2hex(bn.get());
    if (!hex) {
        error = "Cannot convert serial number to hex: " + getOpenSSLError();
        return false;
    }

    out_serial = normalizeHex(hex);
    OPENSSL_free(hex);
    return true;
}

std::string HybridPKIService::computeGGHFingerprint(const hybrid_pki::GGHPublicKey& pub_key) {
    if (pub_key.bad_basis.empty()) {
        return "";
    }

    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE, 0);
    unsigned int digest_len = 0;

    const void* data = pub_key.bad_basis.data();
    const std::size_t data_bytes = pub_key.bad_basis.size() * sizeof(std::int64_t);

    if (EVP_Digest(data, data_bytes, digest.data(), &digest_len, EVP_sha256(), nullptr) != 1) {
        return "";
    }

    std::ostringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    return ss.str();
}

bool HybridPKIService::registerAndBindDevice(const std::string& device_id,
                                            const std::string& certificate_path,
                                            const hybrid_pki::GGHKeyPair& ggh_key_pair,
                                            std::string& error) {
    error.clear();
    if (device_id.empty()) {
        error = "Device identity cannot be empty.";
        return false;
    }
    if (certificate_path.empty() || !std::filesystem::exists(certificate_path)) {
        error = "Certificate file does not exist: " + certificate_path;
        return false;
    }
    if (!ggh_key_pair.has_public_key()) {
        error = "GGH key pair lacks a valid public key.";
        return false;
    }

    // Step 1: Validate certificate chain and revocation against configured trust store
    if (m_trusted_ca_bundle.empty()) {
        error = "Trust store must be configured before registering devices.";
        return false;
    }

    std::string val_err;
    bool cert_valid = m_validator.validateX509CertificateWithRevocation(
        certificate_path, m_trusted_ca_bundle, m_revoked_serials_file, val_err);
    if (!cert_valid) {
        error = "X.509 certificate validation failed during registration: " + val_err;
        return false;
    }

    // Step 2: Extract certificate fingerprint and serial number
    std::string cert_fp;
    if (!CertificateIdentityMapper::certificateFingerprint(certificate_path, cert_fp, val_err)) {
        error = "Failed to calculate certificate fingerprint: " + val_err;
        return false;
    }

    std::string cert_serial;
    if (!extractCertificateSerial(certificate_path, cert_serial, val_err)) {
        error = "Failed to extract certificate serial: " + val_err;
        return false;
    }

    // Step 3: Register identity mapping in Person 2's CertificateIdentityMapper
    if (!m_mapper.addMapping(cert_fp, device_id)) {
        error = "Failed to add certificate-to-device mapping in PKI identity mapper.";
        return false;
    }

    // Step 4: Calculate GGH fingerprint
    std::string ggh_fp = ggh_key_pair.public_fingerprint;
    if (ggh_fp.empty() && ggh_key_pair.public_key) {
        ggh_fp = computeGGHFingerprint(*ggh_key_pair.public_key);
    }
    // Normalize to uppercase
    std::transform(ggh_fp.begin(), ggh_fp.end(), ggh_fp.begin(), ::toupper);

    // Step 5: Construct binding
    HybridDeviceBinding binding;
    binding.device_id = device_id;
    binding.certificate_path = certificate_path;
    binding.certificate_serial = cert_serial;
    binding.x509_fingerprint = cert_fp;
    binding.ggh_fingerprint = ggh_fp;
    binding.binding_id = device_id + ":" + cert_serial + ":" + ggh_fp.substr(0, 8);
    binding.is_active = true;

    m_bindings_by_device[device_id] = binding;
    m_cert_fp_to_device[cert_fp] = device_id;

    return true;
}

bool HybridPKIService::revokeDeviceCertificate(const std::string& serial_hex, std::string& error) {
    error.clear();
    if (serial_hex.empty()) {
        error = "Serial number cannot be empty.";
        return false;
    }
    if (m_revoked_serials_file.empty()) {
        error = "Revocation store is not configured.";
        return false;
    }

    const std::string normalized = normalizeHex(serial_hex);
    if (!m_revocation.revokeCertificateInFile(normalized, m_revoked_serials_file)) {
        error = "Failed to persist certificate serial to revocation list.";
        return false;
    }

    // Deactivate in local binding cache
    for (auto& pair : m_bindings_by_device) {
        if (normalizeHex(pair.second.certificate_serial) == normalized) {
            pair.second.is_active = false;
        }
    }

    return true;
}

bool HybridPKIService::revokeDevice(const std::string& device_id, std::string& error) {
    auto it = m_bindings_by_device.find(device_id);
    if (it == m_bindings_by_device.end()) {
        error = "Device not found: " + device_id;
        return false;
    }
    return revokeDeviceCertificate(it->second.certificate_serial, error);
}

HybridValidationReport HybridPKIService::validateAndVerifyCommand(
    const hybrid_pki::HybridSignedCommand& command,
    const std::string& certificate_path,
    const hybrid_pki::RSAKeyPair& rsa_key_pair,
    const hybrid_pki::GGHKeyPair& ggh_key_pair) {

    HybridValidationReport report;
    report.overall_valid = false;

    if (m_trusted_ca_bundle.empty()) {
        report.error_message = "Trust store not configured in HybridPKIService.";
        return report;
    }

    // -------------------------------------------------------------
    // Step 1: Validate X.509 Certificate Chain (Person 2 Validator)
    // -------------------------------------------------------------
    std::string val_err;
    report.x509_valid = m_validator.validateX509Certificate(
        certificate_path, m_trusted_ca_bundle, val_err);
    if (!report.x509_valid) {
        report.error_message = "X.509 chain verification failed: " + val_err;
        return report;
    }

    // -------------------------------------------------------------
    // Step 2: Validate Certificate Revocation Status (Person 2 Revocation)
    // -------------------------------------------------------------
    report.revocation_checked = true;
    report.not_revoked = m_validator.validateX509CertificateWithRevocation(
        certificate_path, m_trusted_ca_bundle, m_revoked_serials_file, val_err);
    if (!report.not_revoked) {
        report.error_message = "Certificate is revoked: " + val_err;
        return report;
    }

    // -------------------------------------------------------------
    // Step 3: Map Certificate to Authorized Device (Person 2 Identity Mapper)
    // -------------------------------------------------------------
    std::string device_id;
    report.identity_mapped = m_mapper.mapValidatedCertificateToUser(
        certificate_path, m_trusted_ca_bundle, m_revoked_serials_file, device_id, val_err);
    if (!report.identity_mapped || device_id.empty()) {
        report.error_message = "Identity mapping failed: Certificate not bound to any registered device. " + val_err;
        return report;
    }
    report.authenticated_device = device_id;

    // -------------------------------------------------------------
    // Step 4: Verify GGH Public Key Binding to the Authenticated Identity
    // -------------------------------------------------------------
    auto binding_it = m_bindings_by_device.find(device_id);
    if (binding_it == m_bindings_by_device.end() || !binding_it->second.is_active) {
        report.error_message = "No active hybrid binding found for authenticated device: " + device_id;
        return report;
    }

    if (!ggh_key_pair.has_public_key()) {
        report.error_message = "Presented GGH key pair lacks a public key.";
        return report;
    }

    std::string presented_ggh_fp = ggh_key_pair.public_fingerprint;
    if (presented_ggh_fp.empty() && ggh_key_pair.public_key) {
        presented_ggh_fp = computeGGHFingerprint(*ggh_key_pair.public_key);
    }
    std::transform(presented_ggh_fp.begin(), presented_ggh_fp.end(), presented_ggh_fp.begin(), ::toupper);

    const std::string& registered_ggh_fp = binding_it->second.ggh_fingerprint;

    // The GGH fingerprint matches if they are identical or prefix-matches
    bool ggh_matched = (presented_ggh_fp == registered_ggh_fp) ||
                       (!presented_ggh_fp.empty() && !registered_ggh_fp.empty() &&
                        (registered_ggh_fp.find(presented_ggh_fp) == 0 ||
                         presented_ggh_fp.find(registered_ggh_fp) == 0));

    if (!ggh_matched) {
        report.ggh_binding_valid = false;
        report.error_message = "GGH key substitution detected: presented lattice key [" +
                               presented_ggh_fp + "] does not match bound key [" +
                               registered_ggh_fp + "] for device " + device_id;
        return report;
    }
    report.ggh_binding_valid = true;

    // -------------------------------------------------------------
    // Step 5: Verify Hybrid Signatures (Person 1 Cryptographic Engine)
    // -------------------------------------------------------------
    hybrid_pki::HybridVerificationResult crypto_res =
        hybrid_pki::hybridVerify(command, rsa_key_pair, ggh_key_pair);

    report.rsa_signature_valid = crypto_res.rsa_valid;
    report.ggh_signature_valid = crypto_res.ggh_valid;
    report.measurements = crypto_res.measurements;

    if (!report.rsa_signature_valid) {
        report.error_message = "Person 1 RSA-4096 signature verification failed.";
        return report;
    }
    if (!report.ggh_signature_valid) {
        report.error_message = "Person 1 GGH lattice signature verification failed.";
        return report;
    }

    // All checks passed!
    report.overall_valid = true;
    return report;
}

bool HybridPKIService::getBinding(const std::string& device_id, HybridDeviceBinding& out_binding) const {
    auto it = m_bindings_by_device.find(device_id);
    if (it != m_bindings_by_device.end()) {
        out_binding = it->second;
        return true;
    }
    return false;
}

} // namespace hybrid_pki_scada
