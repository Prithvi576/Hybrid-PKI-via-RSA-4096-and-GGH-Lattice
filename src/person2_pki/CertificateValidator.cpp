
#include "CertificateValidator.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

namespace
{
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using StorePtr =
        std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
    using StoreCtxPtr =
        std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

    std::string opensslError()
    {
        const unsigned long code = ERR_get_error();

        if (code == 0) {
            return "no additional OpenSSL error details";
        }

        char buffer[256] = {};
        ERR_error_string_n(code, buffer, sizeof(buffer));
        return std::string(buffer);
    }

    std::string normalizeSerial(std::string serial)
    {
        std::string normalized;

        for (unsigned char c : serial) {
            if (std::isxdigit(c)) {
                normalized.push_back(
                    static_cast<char>(std::toupper(c))
                );
            }
        }

        const std::size_t first = normalized.find_first_not_of('0');

        if (first == std::string::npos) {
            return "0";
        }

        return normalized.substr(first);
    }

    bool readCertificateSerial(
        const std::string& certificatePath,
        std::string& serial,
        std::string& error)
    {
        BioPtr bio(BIO_new_file(certificatePath.c_str(), "rb"), BIO_free);

        if (!bio) {
            error = "Cannot open certificate to read serial: " + opensslError();
            return false;
        }

        X509Ptr cert(
            PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr),
            X509_free
        );

        if (!cert) {
            error = "Cannot parse certificate to read serial: " + opensslError();
            return false;
        }

        BIGNUM* rawNumber = ASN1_INTEGER_to_BN(
            X509_get_serialNumber(cert.get()), nullptr
        );

        BnPtr number(rawNumber, BN_free);

        if (!number) {
            error = "Cannot extract certificate serial: " + opensslError();
            return false;
        }

        char* hex = BN_bn2hex(number.get());

        if (!hex) {
            error = "Cannot encode certificate serial: " + opensslError();
            return false;
        }

        serial = normalizeSerial(hex);
        OPENSSL_free(hex);
        return true;
    }

    bool isSerialRevoked(
        const std::string& serial,
        const std::string& revokedSerialNumbersFile,
        std::string& error)
    {
        std::ifstream file(revokedSerialNumbersFile);

        if (!file) {
            error = "Cannot open revocation list: "
                  + revokedSerialNumbersFile;
            return false;
        }

        const std::string wanted = normalizeSerial(serial);
        std::string line;

        while (std::getline(file, line)) {
            // Allow blank lines and comments in the revocation file.
            const std::size_t comment = line.find('#');

            if (comment != std::string::npos) {
                line.erase(comment);
            }

            const std::size_t first = line.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) {
                continue;
            }

            const std::size_t last = line.find_last_not_of(" \t\r\n");
            line = line.substr(first, last - first + 1);

            if (normalizeSerial(line) == wanted) {
                error = "Certificate has been revoked (serial " + wanted + ").";
                return true;
            }
        }

        return false;
    }
}

CertificateValidator::CertificateValidator()
    : trustedCA("")
{
}

void CertificateValidator::setTrustedCA(const std::string& caName)
{
    trustedCA = caName;
}

bool CertificateValidator::validateIssuer(
    const CertificateManager& certificate) const
{
    return !trustedCA.empty() &&
           certificate.getIssuer() == trustedCA;
}

bool CertificateValidator::validateCertificateFields(
    const CertificateManager& certificate,
    const std::string& expectedSerial) const
{
    return !certificate.getSubject().empty() &&
           !certificate.getIssuer().empty() &&
           !certificate.getSerialNumber().empty() &&
           certificate.getSerialNumber() == expectedSerial;
}

void CertificateValidator::displayValidationResult(bool result) const
{
    // Kept for compatibility with the existing API.
    (void)result;
}

bool CertificateValidator::validateX509Certificate(
    const std::string& certificatePath,
    const std::string& trustedCaBundlePath,
    std::string& error) const
{
    error.clear();
    ERR_clear_error();

    if (certificatePath.empty() || trustedCaBundlePath.empty()) {
        error = "Certificate path and trusted CA bundle path are required.";
        return false;
    }

    BioPtr certificateBio(
        BIO_new_file(certificatePath.c_str(), "rb"), BIO_free
    );

    if (!certificateBio) {
        error = "Cannot open certificate file: " + opensslError();
        return false;
    }

    X509Ptr certificate(
        PEM_read_bio_X509(certificateBio.get(), nullptr, nullptr, nullptr),
        X509_free
    );

    if (!certificate) {
        error = "Cannot parse PEM X.509 certificate: " + opensslError();
        return false;
    }

    StorePtr store(X509_STORE_new(), X509_STORE_free);

    if (!store) {
        error = "Cannot create X.509 trust store: " + opensslError();
        return false;
    }

    if (X509_STORE_load_locations(
            store.get(), trustedCaBundlePath.c_str(), nullptr) != 1) {
        error = "Cannot load trusted CA certificate bundle: " + opensslError();
        return false;
    }

    StoreCtxPtr context(
        X509_STORE_CTX_new(), X509_STORE_CTX_free
    );

    if (!context) {
        error = "Cannot create X.509 verification context: " + opensslError();
        return false;
    }

    if (X509_STORE_CTX_init(
            context.get(), store.get(), certificate.get(), nullptr) != 1) {
        error = "Cannot initialize X.509 verification: " + opensslError();
        return false;
    }

    if (X509_verify_cert(context.get()) != 1) {
        const int code = X509_STORE_CTX_get_error(context.get());
        const char* message = X509_verify_cert_error_string(code);

        error = "X.509 verification failed: ";
        error += message ? message : "unknown verification error";
        return false;
    }

    int critical = -1;
    ASN1_BIT_STRING* usage = static_cast<ASN1_BIT_STRING*>(
        X509_get_ext_d2i(
            certificate.get(), NID_key_usage, &critical, nullptr
        )
    );

    if (!usage) {
        error = "Certificate is missing a valid Key Usage extension.";
        ERR_clear_error();
        return false;
    }

    const bool allowsDigitalSignature =
        ASN1_BIT_STRING_get_bit(usage, 0) != 0;

    ASN1_BIT_STRING_free(usage);

    if (!allowsDigitalSignature) {
        error = "Certificate Key Usage does not permit digital signatures.";
        return false;
    }

    return true;
}

bool CertificateValidator::validateX509CertificateWithRevocation(
    const std::string& certificatePath,
    const std::string& trustedCaBundlePath,
    const std::string& revokedSerialNumbersFile,
    std::string& error) const
{
    error.clear();

    if (!validateX509Certificate(
            certificatePath, trustedCaBundlePath, error)) {
        return false;
    }

    std::string serial;

    if (!readCertificateSerial(certificatePath, serial, error)) {
        return false;
    }

    std::string revocationError;

    if (isSerialRevoked(serial, revokedSerialNumbersFile, revocationError)) {
        error = revocationError;
        return false;
    }

    // Fail closed if the revocation list cannot be read.
    if (!revocationError.empty()) {
        error = revocationError;
        return false;
    }

    return true;
}
