
#include "CertificateIdentityMapper.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <memory>
#include <sstream>

namespace
{
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

    std::string normalizeFingerprint(const std::string& input)
    {
        std::string result;

        for (unsigned char c : input) {
            if (std::isxdigit(c)) {
                result.push_back(
                    static_cast<char>(std::toupper(c))
                );
            }
        }

        return result;
    }
}

bool CertificateIdentityMapper::getSha256Fingerprint(
    const std::string& certificatePath,
    std::string& fingerprint,
    std::string& error)
{
    fingerprint.clear();
    error.clear();

    if (certificatePath.empty()) {
        error = "Certificate path is required.";
        return false;
    }

    BioPtr bio(
        BIO_new_file(certificatePath.c_str(), "rb"),
        BIO_free
    );

    if (!bio) {
        error = "Cannot open certificate file.";
        return false;
    }

    X509Ptr certificate(
        PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr),
        X509_free
    );

    if (!certificate) {
        error = "Cannot parse PEM X.509 certificate.";
        return false;
    }

    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLength = 0;

    if (X509_digest(
            certificate.get(),
            EVP_sha256(),
            digest,
            &digestLength) != 1 ||
        digestLength == 0) {
        error = "Cannot calculate certificate SHA-256 fingerprint.";
        return false;
    }

    std::ostringstream output;
    output << std::uppercase << std::hex << std::setfill('0');

    for (unsigned int i = 0; i < digestLength; ++i) {
        output << std::setw(2)
               << static_cast<unsigned int>(digest[i]);
    }

    fingerprint = output.str();
    return true;
}

bool CertificateIdentityMapper::certificateFingerprint(
    const std::string& certificatePath,
    std::string& fingerprint,
    std::string& error)
{
    return getSha256Fingerprint(
        certificatePath, fingerprint, error
    );
}

bool CertificateIdentityMapper::addMapping(
    const std::string& fingerprint,
    const std::string& userId)
{
    const std::string normalized =
        normalizeFingerprint(fingerprint);

    if (normalized.size() != 64 || userId.empty()) {
        return false;
    }

    // Reject malformed fingerprints rather than accepting arbitrary text.
    for (unsigned char c : fingerprint) {
        if (!std::isxdigit(c) && c != ':' && c != ' ' &&
            c != '\t' && c != '\r' && c != '\n') {
            return false;
        }
    }

    const auto existing = fingerprintToUserId.find(normalized);

    if (existing != fingerprintToUserId.end()) {
        // Do not silently remap an existing certificate to another user.
        return existing->second == userId;
    }

    fingerprintToUserId.emplace(normalized, userId);
    return true;
}

bool CertificateIdentityMapper::mapValidatedCertificateToUser(
    const std::string& certificatePath,
    const std::string& trustedCaBundlePath,
    const std::string& revokedSerialNumbersFile,
    std::string& userId,
    std::string& error) const
{
    userId.clear();
    error.clear();

    CertificateValidator certificateValidator;

    if (!certificateValidator.validateX509CertificateWithRevocation(
            certificatePath,
            trustedCaBundlePath,
            revokedSerialNumbersFile,
            error)) {
        return false;
    }

    std::string fingerprint;

    if (!getSha256Fingerprint(
            certificatePath, fingerprint, error)) {
        return false;
    }

    const auto mapping = fingerprintToUserId.find(fingerprint);

    if (mapping == fingerprintToUserId.end()) {
        error = "Certificate is valid but has no configured identity mapping.";
        return false;
    }

    userId = mapping->second;
    return true;
}
