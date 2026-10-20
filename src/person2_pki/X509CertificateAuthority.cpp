
#include "X509CertificateAuthority.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unordered_set>

namespace
{
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using PKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using PKeyCtxPtr =
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using ReqPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
    using ExtPtr =
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
    using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using Asn1IntPtr =
        std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
    using GeneralNamesPtr =
        std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>;
    using ExtensionsPtr = std::unique_ptr<
        STACK_OF(X509_EXTENSION),
        void (*)(STACK_OF(X509_EXTENSION)*)>;

    std::string opensslError(const std::string& context)
    {
        const unsigned long code = ERR_get_error();

        if (code == 0) {
            return context + ": no additional OpenSSL error details";
        }

        char buffer[256] = {};
        ERR_error_string_n(code, buffer, sizeof(buffer));
        return context + ": " + buffer;
    }

    bool addExtension(
        X509* certificate,
        X509* issuer,
        int nid,
        const char* value,
        std::string& error)
    {
        X509V3_CTX context;
        X509V3_set_ctx(
            &context, issuer, certificate, nullptr, nullptr, 0);
        X509V3_set_ctx_nodb(&context);

        ExtPtr extension(
            X509V3_EXT_conf_nid(
                nullptr, &context, nid, const_cast<char*>(value)),
            X509_EXTENSION_free);

        if (!extension) {
            error = opensslError(
                std::string("Could not create certificate extension: ") +
                OBJ_nid2sn(nid));
            return false;
        }

        if (X509_add_ext(certificate, extension.get(), -1) != 1) {
            error = opensslError(
                std::string("Could not add certificate extension: ") +
                OBJ_nid2sn(nid));
            return false;
        }

        return true;
    }

    bool writeCertificate(
        X509* certificate,
        const std::string& path,
        std::string& error)
    {
        BioPtr output(BIO_new_file(path.c_str(), "wb"), BIO_free);

        if (!output) {
            error = opensslError("Could not open certificate output file");
            return false;
        }

        if (PEM_write_bio_X509(output.get(), certificate) != 1) {
            error = opensslError("Could not write X.509 certificate");
            return false;
        }

        return true;
    }

    bool getCommonName(
        X509_NAME* name,
        std::string& commonName,
        std::string& error)
    {
        const int index =
            X509_NAME_get_index_by_NID(name, NID_commonName, -1);

        if (index < 0) {
            error = "Certificate or CSR subject has no Common Name.";
            return false;
        }

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, index);
        ASN1_STRING* value = X509_NAME_ENTRY_get_data(entry);

        unsigned char* utf8 = nullptr;
        const int length = ASN1_STRING_to_UTF8(&utf8, value);

        if (length < 0 || utf8 == nullptr) {
            OPENSSL_free(utf8);
            error = opensslError("Could not read subject Common Name");
            return false;
        }

        commonName.assign(
            reinterpret_cast<const char*>(utf8),
            static_cast<std::size_t>(length));

        OPENSSL_free(utf8);

        if (commonName.empty()) {
            error = "Subject Common Name cannot be empty.";
            return false;
        }

        return true;
    }

    // Accept exactly one DNS SAN, and require an exact authorization match.
    bool csrContainsAuthorizedDnsName(
        X509_REQ* request,
        const std::string& authorizedDns,
        std::string& error)
    {
        if (authorizedDns.empty()) {
            error = "An authorized DNS SAN is required.";
            return false;
        }

        ExtensionsPtr extensions(
            X509_REQ_get_extensions(request),
            [](STACK_OF(X509_EXTENSION)* stack) {
                if (stack) {
                    sk_X509_EXTENSION_pop_free(
                        stack, X509_EXTENSION_free);
                }
            });

        if (!extensions) {
            error = "CSR does not contain readable extensions.";
            ERR_clear_error();
            return false;
        }

        X509_EXTENSION* sanExtension = nullptr;
        const int count = sk_X509_EXTENSION_num(extensions.get());

        for (int i = 0; i < count; ++i) {
            X509_EXTENSION* extension =
                sk_X509_EXTENSION_value(extensions.get(), i);

            if (OBJ_obj2nid(X509_EXTENSION_get_object(extension)) ==
                NID_subject_alt_name) {
                if (sanExtension != nullptr) {
                    error = "CSR contains duplicate SAN extensions.";
                    return false;
                }
                sanExtension = extension;
            }
        }

        if (!sanExtension) {
            error = "CSR must contain a Subject Alternative Name.";
            return false;
        }

        GeneralNamesPtr names(
            static_cast<GENERAL_NAMES*>(
                X509V3_EXT_d2i(sanExtension)),
            GENERAL_NAMES_free);

        if (!names) {
            error = "CSR Subject Alternative Name is malformed.";
            ERR_clear_error();
            return false;
        }

        if (sk_GENERAL_NAME_num(names.get()) != 1) {
            error = "CSR must contain exactly one authorized DNS SAN.";
            return false;
        }

        GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), 0);

        if (!name || name->type != GEN_DNS) {
            error = "CSR SAN must contain a DNS name only.";
            return false;
        }

        const ASN1_IA5STRING* dnsName = name->d.dNSName;
        const unsigned char* bytes = ASN1_STRING_get0_data(dnsName);
        const int length = ASN1_STRING_length(dnsName);

        if (!bytes || length <= 0 ||
            std::memchr(bytes, '\0',
                        static_cast<std::size_t>(length)) != nullptr) {
            error = "CSR contains an invalid DNS SAN.";
            return false;
        }

        const std::string dns(
            reinterpret_cast<const char*>(bytes),
            static_cast<std::size_t>(length));

        if (dns != authorizedDns) {
            error = "CSR DNS SAN does not match the authorized identity.";
            return false;
        }

        return true;
    }

    bool parseSerial(
        const std::string& serialHex,
        Asn1IntPtr& serial,
        std::string& error)
    {
        if (serialHex.empty()) {
            error = "Certificate serial number is required.";
            return false;
        }

        for (unsigned char c : serialHex) {
            const bool valid =
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F');

            if (!valid) {
                error = "Serial number must contain hexadecimal characters only.";
                return false;
            }
        }

        BIGNUM* rawNumber = nullptr;

        if (BN_hex2bn(&rawNumber, serialHex.c_str()) == 0 ||
            rawNumber == nullptr) {
            BN_free(rawNumber);
            error = "Could not parse certificate serial number.";
            return false;
        }

        BnPtr number(rawNumber, BN_free);

        if (BN_is_zero(number.get()) ||
            BN_is_negative(number.get()) ||
            BN_num_bytes(number.get()) > 20) {
            error = "Serial number must be positive, nonzero, and at most 20 bytes.";
            return false;
        }

        ASN1_INTEGER* rawSerial =
            BN_to_ASN1_INTEGER(number.get(), nullptr);

        if (!rawSerial) {
            error = opensslError("Could not create ASN.1 serial number");
            return false;
        }

        serial = Asn1IntPtr(rawSerial, ASN1_INTEGER_free);
        return true;
    }

    // Normalize an ASN.1 serial number to hexadecimal for duplicate checks.
    // This prevents leading zeros or letter case from bypassing the check.
    std::string canonicalSerialHex(
        const ASN1_INTEGER* serial,
        std::string& error)
    {
        BIGNUM* rawNumber = ASN1_INTEGER_to_BN(serial, nullptr);

        if (!rawNumber) {
            error = opensslError("Could not normalize certificate serial");
            return {};
        }

        BnPtr number(rawNumber, BN_free);
        char* rawHex = BN_bn2hex(number.get());

        if (!rawHex) {
            error = opensslError("Could not encode certificate serial");
            return {};
        }

        std::string result(rawHex);
        OPENSSL_free(rawHex);
        return result;
    }

    constexpr const char* SERIAL_REGISTRY_HEADER = "PKI_SERIAL_REGISTRY_V1";

    std::string serialRegistryPath(const std::string& caCertificatePath)
    {
        return caCertificatePath + ".serials";
    }

    bool readSerialRegistry(
        const std::string& path,
        std::unordered_set<std::string>& serials,
        std::string& error)
    {
        std::ifstream input(path);

        if (!input) {
            error = "Could not open CA serial registry: " + path;
            return false;
        }

        std::string line;
        if (!std::getline(input, line) ||
            line != SERIAL_REGISTRY_HEADER) {
            error = "CA serial registry has an invalid or missing header.";
            return false;
        }

        std::unordered_set<std::string> loaded;
        while (std::getline(input, line)) {
            if (line.empty()) {
                error = "CA serial registry contains an empty entry.";
                return false;
            }

            for (unsigned char c : line) {
                const bool valid =
                    (c >= '0' && c <= '9') ||
                    (c >= 'A' && c <= 'F');
                if (!valid) {
                    error = "CA serial registry contains an invalid serial.";
                    return false;
                }
            }

            if (!loaded.insert(line).second) {
                error = "CA serial registry contains duplicate entries.";
                return false;
            }
        }

        if (input.bad()) {
            error = "Could not read the complete CA serial registry.";
            return false;
        }

        serials = std::move(loaded);
        return true;
    }

    bool initializeSerialRegistry(
        const std::string& path,
        std::string& error)
    {
        std::ofstream output(path, std::ios::out | std::ios::trunc);
        if (!output) {
            error = "Could not create CA serial registry: " + path;
            return false;
        }

        output << SERIAL_REGISTRY_HEADER << '\n';
        output.flush();

        if (!output) {
            error = "Could not initialize CA serial registry: " + path;
            return false;
        }

        return true;
    }

    bool appendSerialToRegistry(
        const std::string& path,
        const std::string& serial,
        std::string& error)
    {
        std::ofstream output(path, std::ios::out | std::ios::app);
        if (!output) {
            error = "Could not open CA serial registry for update: " + path;
            return false;
        }

        output << serial << '\n';
        output.flush();

        if (!output) {
            error = "Could not persist issued serial in CA registry: " + path;
            return false;
        }

        return true;
    }

    bool validateLoadedRootCA(X509* certificate, std::string& error)
    {
        if (X509_check_ca(certificate) <= 0) {
            error = "Loaded certificate is not marked as a CA certificate.";
            return false;
        }

        if (X509_NAME_cmp(
                X509_get_subject_name(certificate),
                X509_get_issuer_name(certificate)) != 0) {
            error = "CA certificate is not self-issued.";
            return false;
        }

        PKeyPtr publicKey(X509_get_pubkey(certificate), EVP_PKEY_free);

        if (!publicKey ||
            X509_verify(certificate, publicKey.get()) != 1) {
            error = "CA certificate self-signature verification failed.";
            ERR_clear_error();
            return false;
        }

        const int notBefore =
            X509_cmp_current_time(X509_get0_notBefore(certificate));
        const int notAfter =
            X509_cmp_current_time(X509_get0_notAfter(certificate));

        if (notBefore == 0 || notBefore > 0 ||
            notAfter == 0 || notAfter < 0) {
            error = "CA certificate is not currently valid.";
            return false;
        }

        BASIC_CONSTRAINTS* constraints =
            static_cast<BASIC_CONSTRAINTS*>(
                X509_get_ext_d2i(
                    certificate, NID_basic_constraints,
                    nullptr, nullptr));

        if (!constraints || constraints->ca == 0) {
            BASIC_CONSTRAINTS_free(constraints);
            error = "CA certificate lacks valid CA:TRUE constraints.";
            return false;
        }

        BASIC_CONSTRAINTS_free(constraints);

        ASN1_BIT_STRING* keyUsage =
            static_cast<ASN1_BIT_STRING*>(
                X509_get_ext_d2i(
                    certificate, NID_key_usage,
                    nullptr, nullptr));

        if (!keyUsage ||
            ASN1_BIT_STRING_get_bit(keyUsage, 5) != 1) {
            ASN1_BIT_STRING_free(keyUsage);
            error = "CA certificate must permit certificate signing.";
            return false;
        }

        ASN1_BIT_STRING_free(keyUsage);
        return true;
    }
}

X509CertificateAuthority::X509CertificateAuthority()
    : caPrivateKey(nullptr),
      caCertificate(nullptr),
      caName(),
      privateKeyPath(),
      certificatePath()
{
}

X509CertificateAuthority::~X509CertificateAuthority()
{
    clear();
}

void X509CertificateAuthority::clear() noexcept
{
    EVP_PKEY_free(caPrivateKey);
    X509_free(caCertificate);

    caPrivateKey = nullptr;
    caCertificate = nullptr;

    caName.clear();
    privateKeyPath.clear();
    certificatePath.clear();
    issuedSerials.clear();
}

bool X509CertificateAuthority::createCA(
    const std::string& commonName,
    const std::string& privateKeyFile,
    const std::string& certificateFile,
    const std::string& passphrase,
    int validityDays,
    std::string& error)
{
    error.clear();
    ERR_clear_error();

    if (commonName.empty() ||
        privateKeyFile.empty() ||
        certificateFile.empty()) {
        error = "CA Common Name and output paths are required.";
        return false;
    }

    if (privateKeyFile == certificateFile) {
        error = "Private key and certificate must use different files.";
        return false;
    }

    if (passphrase.size() < 12) {
        error = "CA passphrase must contain at least 12 characters.";
        return false;
    }

    if (validityDays < 1 || validityDays > 3650) {
        error = "CA validity must be between 1 and 3650 days.";
        return false;
    }

    PKeyCtxPtr keyContext(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
        EVP_PKEY_CTX_free);

    if (!keyContext ||
        EVP_PKEY_keygen_init(keyContext.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 4096) <= 0) {
        error = opensslError("Could not initialize RSA-4096 key generation");
        return false;
    }

    EVP_PKEY* rawKey = nullptr;

    if (EVP_PKEY_keygen(keyContext.get(), &rawKey) <= 0 ||
        rawKey == nullptr) {
        EVP_PKEY_free(rawKey);
        error = opensslError("Could not generate CA private key");
        return false;
    }

    PKeyPtr key(rawKey, EVP_PKEY_free);
    X509Ptr certificate(X509_new(), X509_free);

    if (!certificate) {
        error = opensslError("Could not create CA certificate");
        return false;
    }

    if (X509_set_version(certificate.get(), 2) != 1) {
        error = opensslError("Could not set CA certificate version");
        return false;
    }

    BIGNUM* rawSerialNumber = BN_new();

    if (!rawSerialNumber ||
        BN_rand(rawSerialNumber, 159, BN_RAND_TOP_ONE,
                BN_RAND_BOTTOM_ODD) != 1) {
        BN_free(rawSerialNumber);
        error = opensslError("Could not generate CA certificate serial");
        return false;
    }

    BnPtr serialNumber(rawSerialNumber, BN_free);
    Asn1IntPtr asn1Serial(
        BN_to_ASN1_INTEGER(serialNumber.get(), nullptr),
        ASN1_INTEGER_free);

    if (!asn1Serial ||
        X509_set_serialNumber(certificate.get(), asn1Serial.get()) != 1) {
        error = opensslError("Could not set CA certificate serial");
        return false;
    }

    if (X509_gmtime_adj(
            X509_getm_notBefore(certificate.get()), -300) == nullptr ||
        X509_gmtime_adj(
            X509_getm_notAfter(certificate.get()),
            static_cast<long>(validityDays) * 24L * 60L * 60L) == nullptr) {
        error = opensslError("Could not set CA certificate validity");
        return false;
    }

    if (X509_set_pubkey(certificate.get(), key.get()) != 1) {
        error = opensslError("Could not set CA public key");
        return false;
    }

    X509_NAME* subject = X509_get_subject_name(certificate.get());

    if (!subject ||
        X509_NAME_add_entry_by_txt(
            subject, "CN", MBSTRING_UTF8,
            reinterpret_cast<const unsigned char*>(commonName.c_str()),
            -1, -1, 0) != 1 ||
        X509_set_issuer_name(certificate.get(), subject) != 1) {
        error = opensslError("Could not set CA certificate subject");
        return false;
    }

    if (!addExtension(
            certificate.get(), certificate.get(),
            NID_basic_constraints, "critical,CA:TRUE,pathlen:1", error) ||
        !addExtension(
            certificate.get(), certificate.get(),
            NID_key_usage, "critical,keyCertSign,cRLSign", error) ||
        !addExtension(
            certificate.get(), certificate.get(),
            NID_subject_key_identifier, "hash", error) ||
        !addExtension(
            certificate.get(), certificate.get(),
            NID_authority_key_identifier, "keyid:always", error)) {
        return false;
    }

    if (X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0) {
        error = opensslError("Could not sign CA certificate");
        return false;
    }

    {
        BioPtr keyOutput(
            BIO_new_file(privateKeyFile.c_str(), "wb"), BIO_free);

        if (!keyOutput) {
            error = opensslError("Could not open CA private-key output file");
            return false;
        }

        if (PEM_write_bio_PrivateKey(
                keyOutput.get(), key.get(), EVP_aes_256_cbc(),
                reinterpret_cast<unsigned char*>(
                    const_cast<char*>(passphrase.data())),
                static_cast<int>(passphrase.size()),
                nullptr, nullptr) != 1) {
            error = opensslError("Could not write encrypted CA private key");
            return false;
        }
    }

    if (!writeCertificate(certificate.get(), certificateFile, error)) {
        return false;
    }

    if (!initializeSerialRegistry(
            serialRegistryPath(certificateFile), error)) {
        return false;
    }

    clear();

    caPrivateKey = key.release();
    caCertificate = certificate.release();
    caName = commonName;
    privateKeyPath = privateKeyFile;
    certificatePath = certificateFile;

    return true;
}

bool X509CertificateAuthority::loadCA(
    const std::string& privateKeyFile,
    const std::string& certificateFile,
    const std::string& passphrase,
    std::string& error)
{
    error.clear();
    ERR_clear_error();

    if (privateKeyFile.empty() ||
        certificateFile.empty() ||
        passphrase.empty()) {
        error = "CA key path, certificate path, and passphrase are required.";
        return false;
    }

    BioPtr keyInput(BIO_new_file(privateKeyFile.c_str(), "rb"), BIO_free);

    if (!keyInput) {
        error = opensslError("Could not open CA private-key file");
        return false;
    }

    PKeyPtr key(
        PEM_read_bio_PrivateKey(
            keyInput.get(), nullptr, nullptr,
            const_cast<char*>(passphrase.c_str())),
        EVP_PKEY_free);

    if (!key) {
        error = opensslError("Could not load CA private key");
        return false;
    }

    BioPtr certificateInput(
        BIO_new_file(certificateFile.c_str(), "rb"), BIO_free);

    if (!certificateInput) {
        error = opensslError("Could not open CA certificate file");
        return false;
    }

    X509Ptr certificate(
        PEM_read_bio_X509(
            certificateInput.get(), nullptr, nullptr, nullptr),
        X509_free);

    if (!certificate) {
        error = opensslError("Could not parse CA certificate");
        return false;
    }

    if (X509_check_private_key(certificate.get(), key.get()) != 1) {
        error = opensslError(
            "CA private key does not match the certificate");
        return false;
    }

    if (!validateLoadedRootCA(certificate.get(), error)) {
        return false;
    }

    std::string commonName;

    if (!getCommonName(
            X509_get_subject_name(certificate.get()),
            commonName, error)) {
        return false;
    }

    std::unordered_set<std::string> loadedSerials;
    if (!readSerialRegistry(
            serialRegistryPath(certificateFile), loadedSerials, error)) {
        return false;
    }

    clear();

    caPrivateKey = key.release();
    caCertificate = certificate.release();
    caName = commonName;
    privateKeyPath = privateKeyFile;
    certificatePath = certificateFile;
    issuedSerials = std::move(loadedSerials);

    return true;
}

bool X509CertificateAuthority::isReady() const
{
    return caPrivateKey != nullptr &&
           caCertificate != nullptr &&
           X509_check_private_key(caCertificate, caPrivateKey) == 1 &&
           X509_check_ca(caCertificate) > 0;
}

const std::string& X509CertificateAuthority::getCAName() const
{
    return caName;
}

const std::string& X509CertificateAuthority::getCertificatePath() const
{
    return certificatePath;
}

bool X509CertificateAuthority::issueCertificateFromCSR(
    const std::string& csrFile,
    const std::string& outputCertificateFile,
    const std::string& authorizedCommonName,
    const std::string& authorizedSanDns,
    const std::string& serialNumberHex,
    int validityDays,
    std::string& error)
{
    error.clear();
    ERR_clear_error();

    if (!isReady()) {
        error = "CA is not loaded and ready.";
        return false;
    }

    if (csrFile.empty() ||
        outputCertificateFile.empty() ||
        authorizedCommonName.empty() ||
        authorizedSanDns.empty()) {
        error = "CSR path, output path, and authorized identities are required.";
        return false;
    }

    if (outputCertificateFile == privateKeyPath ||
        outputCertificateFile == certificatePath) {
        error = "Output certificate path must not overwrite CA key or certificate.";
        return false;
    }

    if (validityDays < 1 || validityDays > 397) {
        error = "Issued certificate validity must be between 1 and 397 days.";
        return false;
    }

    BioPtr csrInput(BIO_new_file(csrFile.c_str(), "rb"), BIO_free);

    if (!csrInput) {
        error = opensslError("Could not open CSR file");
        return false;
    }

    ReqPtr request(
        PEM_read_bio_X509_REQ(csrInput.get(), nullptr, nullptr, nullptr),
        X509_REQ_free);

    if (!request) {
        error = opensslError("Could not parse PEM CSR");
        return false;
    }

    PKeyPtr requestPublicKey(
        X509_REQ_get_pubkey(request.get()),
        EVP_PKEY_free);

    if (!requestPublicKey) {
        error = opensslError("CSR does not contain a readable public key");
        return false;
    }

    if (X509_REQ_verify(request.get(), requestPublicKey.get()) != 1) {
        error = opensslError("CSR self-signature verification failed");
        return false;
    }

    std::string requestedCommonName;

    if (!getCommonName(
            X509_REQ_get_subject_name(request.get()),
            requestedCommonName, error)) {
        return false;
    }

    if (requestedCommonName != authorizedCommonName) {
        error = "CSR Common Name does not match the authorized identity.";
        return false;
    }

    if (!csrContainsAuthorizedDnsName(
            request.get(), authorizedSanDns, error)) {
        return false;
    }

    Asn1IntPtr serial(nullptr, ASN1_INTEGER_free);

    if (!parseSerial(serialNumberHex, serial, error)) {
        return false;
    }

    const std::string canonicalSerial =
        canonicalSerialHex(serial.get(), error);

    if (canonicalSerial.empty()) {
        return false;
    }

    if (issuedSerials.find(canonicalSerial) != issuedSerials.end()) {
        error = "Duplicate certificate serial number.";
        return false;
    }

    X509Ptr certificate(X509_new(), X509_free);

    if (!certificate) {
        error = opensslError("Could not allocate issued certificate");
        return false;
    }

    if (X509_set_version(certificate.get(), 2) != 1 ||
        X509_set_serialNumber(certificate.get(), serial.get()) != 1 ||
        X509_set_issuer_name(
            certificate.get(),
            X509_get_subject_name(caCertificate)) != 1 ||
        X509_set_subject_name(
            certificate.get(),
            X509_REQ_get_subject_name(request.get())) != 1 ||
        X509_set_pubkey(certificate.get(), requestPublicKey.get()) != 1) {
        error = opensslError("Could not set issued certificate fields");
        return false;
    }

    if (X509_gmtime_adj(
            X509_getm_notBefore(certificate.get()), -300) == nullptr ||
        X509_gmtime_adj(
            X509_getm_notAfter(certificate.get()),
            static_cast<long>(validityDays) * 24L * 60L * 60L) == nullptr) {
        error = opensslError("Could not set issued certificate validity");
        return false;
    }

    if (!addExtension(
            certificate.get(), caCertificate,
            NID_basic_constraints, "critical,CA:FALSE", error) ||
        !addExtension(
            certificate.get(), caCertificate,
            NID_key_usage,
            "critical,digitalSignature,keyEncipherment", error) ||
        !addExtension(
            certificate.get(), caCertificate,
            NID_ext_key_usage, "clientAuth", error) ||
        !addExtension(
            certificate.get(), caCertificate,
            NID_subject_alt_name,
            ("DNS:" + authorizedSanDns).c_str(), error) ||
        !addExtension(
            certificate.get(), caCertificate,
            NID_subject_key_identifier, "hash", error) ||
        !addExtension(
            certificate.get(), caCertificate,
            NID_authority_key_identifier, "keyid:always", error)) {
        return false;
    }

    if (X509_sign(certificate.get(), caPrivateKey, EVP_sha256()) <= 0) {
        error = opensslError("Could not sign issued X.509 certificate");
        return false;
    }

    // Reserve the serial durably before writing the certificate. If writing
    // the certificate later fails, the serial remains reserved rather than
    // risking reuse after a restart.
    if (!appendSerialToRegistry(
            serialRegistryPath(certificatePath), canonicalSerial, error)) {
        // Reserve in memory too, in case the registry write was partial.
        issuedSerials.insert(canonicalSerial);
        return false;
    }

    issuedSerials.insert(canonicalSerial);

    if (!writeCertificate(
            certificate.get(), outputCertificateFile, error)) {
        return false;
    }

    return true;
}
