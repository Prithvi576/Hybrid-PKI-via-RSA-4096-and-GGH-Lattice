
#ifndef X509_CERTIFICATE_AUTHORITY_H
#define X509_CERTIFICATE_AUTHORITY_H

#include <string>
#include <unordered_set>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

class X509CertificateAuthority
{
private:
    EVP_PKEY* caPrivateKey;
    X509* caCertificate;

    std::string caName;
    std::string privateKeyPath;
    std::string certificatePath;

    // Tracks serial numbers issued during this object's lifetime.
    std::unordered_set<std::string> issuedSerials;

    // Prevent copying of objects that own OpenSSL resources.
    X509CertificateAuthority(const X509CertificateAuthority&) = delete;

    X509CertificateAuthority& operator=(
        const X509CertificateAuthority&) = delete;

public:
    X509CertificateAuthority();
    ~X509CertificateAuthority();

    // Generate an RSA-4096 CA key and a self-signed CA certificate.
    // The private key is encrypted using the supplied passphrase.
    bool createCA(
        const std::string& commonName,
        const std::string& privateKeyFile,
        const std::string& certificateFile,
        const std::string& passphrase,
        int validityDays,
        std::string& error
    );

    // Load an existing CA certificate and encrypted private key.
    bool loadCA(
        const std::string& privateKeyFile,
        const std::string& certificateFile,
        const std::string& passphrase,
        std::string& error
    );

    // Check whether the CA key and certificate are loaded and match.
    bool isReady() const;

    const std::string& getCAName() const;
    const std::string& getCertificatePath() const;

    // Validate and sign a CSR only when its requested identity is authorized.
    bool issueCertificateFromCSR(
        const std::string& csrFile,
        const std::string& outputCertificateFile,
        const std::string& authorizedCommonName,
        const std::string& authorizedSanDns,
        const std::string& serialNumberHex,
        int validityDays,
        std::string& error
    );

private:
    // Release the active CA resources and reset associated state.
    void clear() noexcept;
};

#endif // X509_CERTIFICATE_AUTHORITY_H
