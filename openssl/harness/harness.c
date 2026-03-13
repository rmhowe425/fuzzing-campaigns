#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/provider.h>

#define MAX_BUF 65536   // Max fuzz input size

static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;
static BIO *rbio = NULL;
static BIO *wbio = NULL;
static int initialized = 0;

// Initialize OpenSSL and create persistent SSL objects
static void init_openssl(void) {
    if (initialized)
        return;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_method()); // TLS client/server capable
    if (!ctx) exit(1);

    // Create SSL object with memory BIOs
    ssl = SSL_new(ctx);
    if (!ssl) exit(1);

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio) exit(1);

    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_accept_state(ssl); // server mode

    initialized = 1;
}

// Reset SSL state between fuzz iterations
static void reset_ssl(void) {
    SSL_shutdown(ssl);
    SSL_clear(ssl);
    BIO_reset(rbio);
    BIO_reset(wbio);
    ERR_clear_error();
}

// Persistent AFL++ entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_BUF)
        return 0;

    init_openssl();

    // --- Stage 1: fuzz EVP provider fetches ---
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    EVP_MD *digest = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (cipher) EVP_CIPHER_free(cipher);
    if (digest) EVP_MD_free(digest);

    // --- Stage 2: fuzz certificate parsing ---
    const uint8_t *ptr = data;
    X509 *cert = d2i_X509(NULL, &ptr, (long)size);
    if (cert) {
        SSL_CTX_use_certificate(ctx, cert);
        X509_free(cert);
    }

    // --- Stage 3: fuzz handshake and multi-message TLS ---
    // Feed fuzzed data into memory BIO
    BIO_write(rbio, data, (int)size);

    // Attempt handshake
    SSL_do_handshake(ssl);

    // Attempt SSL_read and SSL_write
    char buf[4096];
    SSL_read(ssl, buf, sizeof(buf));
    SSL_write(ssl, data, (int)size);

    // Reset SSL for next iteration
    reset_ssl();

    return 0;
}

// AFL++ persistent mode entry
int main(int argc, char **argv) {
    uint8_t buf[MAX_BUF];
    size_t n;

    // AFL++ persistent loop
    while (__AFL_LOOP(1000)) {
        n = fread(buf, 1, MAX_BUF, stdin);
        LLVMFuzzerTestOneInput(buf, n);
    }
    return 0;
}
