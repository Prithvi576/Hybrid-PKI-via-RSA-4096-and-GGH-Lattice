
#include "X509CertificateAuthority.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using ReqPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

static int passed = 0;
static int failed = 0;

void report(const std::string& name, bool ok, const std::string& error = "")
{
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!ok && !error.empty()) {
        std::cout << "       " << error << '\n';
    }
    ok ? ++passed : ++failed;
}

KeyPtr generateRSAKey(int bits)
{
    EVP_PKEY_CTX* rawContext =
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!rawContext) {
        return KeyPtr(nullptr, EVP_PKEY_free);
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
        context(rawContext, EVP_PKEY_CTX_free);

    EVP_PKEY* rawKey = nullptr;

    if (EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), bits) <= 0 ||
        EVP_PKEY_keygen(context.get(), &rawKey) <= 0) {
        EVP_PKEY_free(rawKey);
        return KeyPtr(nullptr, EVP_PKEY_free);
    }

    return KeyPtr(rawKey, EVP_PKEY_free);
}

bool writeCSR(
    const fs::path& path,
    const std::string& commonName,
    const std::vector<std::string>& dnsNames)
{
    KeyPtr key = generateRSAKey(2048);
    if (!key) return false;

    ReqPtr request(X509_REQ_new(), X509_REQ_free);
    if (!request ||
        X509_REQ_set_version(request.get(), 0) != 1 ||
        X509_REQ_set_pubkey(request.get(), key.get()) != 1) {
        return false;
    }

    X509_NAME* subject = X509_REQ_get_subject_name(request.get());

    if (!subject ||
        X509_NAME_add_entry_by_txt(
            subject, "CN", MBSTRING_UTF8,
            reinterpret_cast<const unsigned char*>(commonName.c_str()),
            -1, -1, 0) != 1) {
        return false;
    }

    GENERAL_NAMES* rawNames = sk_GENERAL_NAME_new_null();
    if (!rawNames) return false;

    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>
        names(rawNames, GENERAL_NAMES_free);

    for (const std::string& dns : dnsNames) {
        GENERAL_NAME* name = GENERAL_NAME_new();
        ASN1_IA5STRING* value = ASN1_IA5STRING_new();

        if (!name || !value ||
            ASN1_STRING_set(
                value, dns.data(), static_cast<int>(dns.size())) != 1) {
            GENERAL_NAME_free(name);
            ASN1_IA5STRING_free(value);
            return false;
        }

        GENERAL_NAME_set0_value(name, GEN_DNS, value);

        if (!sk_GENERAL_NAME_push(names.get(), name)) {
            GENERAL_NAME_free(name);
            return false;
        }
    }

    X509_EXTENSION* san = X509V3_EXT_i2d(
        NID_subject_alt_name, 0, names.get());

    if (!san) return false;

    STACK_OF(X509_EXTENSION)* rawExtensions =
        sk_X509_EXTENSION_new_null();

    if (!rawExtensions) {
        X509_EXTENSION_free(san);
        return false;
    }

    std::unique_ptr<
        STACK_OF(X509_EXTENSION),
        void (*)(STACK_OF(X509_EXTENSION)*)>
        extensions(rawExtensions, [](STACK_OF(X509_EXTENSION)* stack) {
            if (stack) {
                sk_X509_EXTENSION_pop_free(stack, X509_EXTENSION_free);
            }
        });

    if (!sk_X509_EXTENSION_push(extensions.get(), san)) {
        X509_EXTENSION_free(san);
        return false;
    }

    if (X509_REQ_add_extensions(request.get(), extensions.get()) != 1 ||
        X509_REQ_sign(request.get(), key.get(), EVP_sha256()) <= 0) {
        return false;
    }

    BioPtr output(
        BIO_new_file(path.string().c_str(), "wb"), BIO_free);

    return output &&
           PEM_write_bio_X509_REQ(output.get(), request.get()) == 1;
}

bool verifyCertificateChain(
    const fs::path& caPath,
    const fs::path& issuedPath)
{
    BioPtr caInput(BIO_new_file(caPath.string().c_str(), "rb"), BIO_free);
    BioPtr certInput(
        BIO_new_file(issuedPath.string().c_str(), "rb"), BIO_free);

    if (!caInput || !certInput) return false;

    CertPtr ca(PEM_read_bio_X509(caInput.get(), nullptr, nullptr, nullptr),
               X509_free);
    CertPtr cert(
        PEM_read_bio_X509(certInput.get(), nullptr, nullptr, nullptr),
        X509_free);

    if (!ca || !cert) return false;

    X509_STORE* rawStore = X509_STORE_new();
    if (!rawStore) return false;

    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>
        store(rawStore, X509_STORE_free);

    if (X509_STORE_add_cert(store.get(), ca.get()) != 1) return false;

    X509_STORE_CTX* rawContext = X509_STORE_CTX_new();
    if (!rawContext) return false;

    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>
        context(rawContext, X509_STORE_CTX_free);

    if (X509_STORE_CTX_init(
            context.get(), store.get(), cert.get(), nullptr) != 1) {
        return false;
    }

    return X509_verify_cert(context.get()) == 1;
}

int main()
{
    const fs::path dir =
        fs::temp_directory_path() / "person2_x509_ca_tests";

    std::error_code ec;
    fs::remove_all(dir, ec);
    ec.clear();

    if (!fs::create_directories(dir, ec) || ec) {
        std::cerr << "Could not create temporary test directory.\n";
        return 1;
    }

    const fs::path keyPath = dir / "ca_key.pem";
    const fs::path caPath = dir / "ca_cert.pem";
    const fs::path csrPath = dir / "client.csr";
    const fs::path issuedPath = dir / "issued.pem";
    const fs::path wrongCnCsr = dir / "wrong_cn.csr";
    const fs::path extraSanCsr = dir / "extra_san.csr";
    const std::string passphrase = "Test-CA-Passphrase-2026";

    std::string error;
    X509CertificateAuthority ca;

    const bool created = ca.createCA(
        "SCADA-Test-Root",
        keyPath.string(),
        caPath.string(),
        passphrase,
        365,
        error);

    report("Create RSA-4096 test CA", created, error);
    report("New CA reports ready", created && ca.isReady());

    X509CertificateAuthority wrongPass;
    error.clear();

    const bool wrongPassRejected =
        !wrongPass.loadCA(
            keyPath.string(),
            caPath.string(),
            "Incorrect-Passphrase",
            error);

    report("Incorrect CA passphrase rejected", wrongPassRejected, error);

    X509CertificateAuthority loaded;
    error.clear();

    const bool loadedOK = loaded.loadCA(
        keyPath.string(),
        caPath.string(),
        passphrase,
        error);

    report("Correct CA key and certificate load", loadedOK, error);
    report("Loaded CA reports ready", loadedOK && loaded.isReady());

    error.clear();
    const bool csrCreated =
        writeCSR(csrPath, "scada-client-01", {"scada-client-01.example.test"});

    report("Generate authorized client CSR", csrCreated);

    bool issued = false;
    if (loadedOK && csrCreated) {
        error.clear();
        issued = loaded.issueCertificateFromCSR(
            csrPath.string(),
            issuedPath.string(),
            "scada-client-01",
            "scada-client-01.example.test",
            "1001",
            30,
            error);
    }

    report("Authorized CSR certificate issuance", issued, error);

    report(
        "Issued certificate chains to test CA",
        issued && verifyCertificateChain(caPath, issuedPath));

        error.clear();

    const bool duplicateRejected =
        loadedOK && csrCreated &&
        !loaded.issueCertificateFromCSR(
            csrPath.string(),
            (dir / "duplicate_serial.pem").string(),
            "scada-client-01",
            "scada-client-01.example.test",
            "01001",
            30,
            error);

    report(
        "Duplicate serial number rejected",
        duplicateRejected,
        error);

    X509CertificateAuthority reloadedAfterIssuance;
    error.clear();

    const bool reloadedAfterIssueOK =
        reloadedAfterIssuance.loadCA(
            keyPath.string(),
            caPath.string(),
            passphrase,
            error);

    error.clear();
    const bool duplicateRejectedAfterReload =
        reloadedAfterIssueOK && csrCreated &&
        !reloadedAfterIssuance.issueCertificateFromCSR(
            csrPath.string(),
            (dir / "duplicate_after_reload.pem").string(),
            "scada-client-01",
            "scada-client-01.example.test",
            "01001",
            30,
            error);

    report(
        "Duplicate serial rejected after CA reload",
        duplicateRejectedAfterReload,
        error);
    const bool wrongCsrCreated =
        writeCSR(wrongCnCsr, "unauthorized-client", {"scada-client-01.example.test"});

    bool wrongCnRejected = false;
    if (loadedOK && wrongCsrCreated) {
        error.clear();
        wrongCnRejected = !loaded.issueCertificateFromCSR(
            wrongCnCsr.string(),
            (dir / "wrong_cn_issued.pem").string(),
            "scada-client-01",
            "scada-client-01.example.test",
            "1002",
            30,
            error);
    }

    report("Unauthorized Common Name rejected", wrongCnRejected, error);

    error.clear();
    const bool extraSanCreated = writeCSR(
        extraSanCsr,
        "scada-client-01",
        {"scada-client-01.example.test", "unauthorized.example.test"});

    bool extraSanRejected = false;
    if (loadedOK && extraSanCreated) {
        error.clear();
        extraSanRejected = !loaded.issueCertificateFromCSR(
            extraSanCsr.string(),
            (dir / "extra_san_issued.pem").string(),
            "scada-client-01",
            "scada-client-01.example.test",
            "1003",
            30,
            error);
    }

    report("Additional unauthorized DNS SAN rejected", extraSanRejected, error);

    const fs::path registryPath = caPath.string() + ".serials";
    const fs::path savedRegistryPath = caPath.string() + ".serials.saved";
    std::error_code registryEc;
    fs::rename(registryPath, savedRegistryPath, registryEc);

    bool missingRegistryRejected = false;
    if (!registryEc) {
        X509CertificateAuthority withoutRegistry;
        error.clear();
        missingRegistryRejected =
            !withoutRegistry.loadCA(
                keyPath.string(),
                caPath.string(),
                passphrase,
                error);
        std::error_code restoreEc;
        fs::rename(savedRegistryPath, registryPath, restoreEc);
        registryEc = restoreEc;
    }

    report(
        "Missing serial registry fails closed",
        missingRegistryRejected && !registryEc,
        error);

    std::cout << "\n===== X.509 CA TEST RESULTS =====\n"
              << "Passed: " << passed << '\n'
              << "Failed: " << failed << '\n'
              << "Total : " << passed + failed << '\n';

    fs::remove_all(dir, ec);
    return failed == 0 ? 0 : 1;
}
