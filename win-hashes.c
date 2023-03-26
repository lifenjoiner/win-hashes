/* Windows hashes wrapper.
   @: YX Hao
   #: 20200616
*/


#include <windows.h>
#include <wincrypt.h>

#include "win-hashes.h"

/* Ref:
    https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
    https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-provider-types

PROV_RSA_AES Hashing:
MD2
MD4
MD5
SHA-1
SHA-2 (SHA-256, SHA-384, and SHA-512)
*/
void hash_init(ALG_ID id, CRYPT_CTX *ctx) {
    if (CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptCreateHash(ctx->hCryptProv, id, 0, 0, &ctx->hHash);
    }
}

void hash_update(CRYPT_CTX *ctx, const void *data, unsigned int len) {
    CryptHashData(ctx->hHash, (const BYTE *)data, (DWORD)len, 0);
}

void * hash_final(CRYPT_CTX *ctx, void *digest) {
    DWORD length;

    // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgethashparam
    if (CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0)) { // <-- finish and get result length
        CryptGetHashParam(ctx->hHash, HP_HASHVAL, (BYTE *)digest, &length, 0);
    }
    if (ctx->hHash) CryptDestroyHash(ctx->hHash);
    if (ctx->hCryptProv) CryptReleaseContext(ctx->hCryptProv, 0);

    return digest;
}


void * hash_buffer(ALG_ID id, const void *buffer, unsigned int len, void *digest) {
    CRYPT_CTX ctx;

    hash_init(id, &ctx);
    hash_update(&ctx, buffer, len);
    return hash_final(&ctx, digest);
}
