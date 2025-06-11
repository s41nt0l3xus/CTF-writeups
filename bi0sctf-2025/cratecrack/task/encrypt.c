#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <secp256k1.h>

/*--------------------------------------------------------------------*/
/* 1.  very small helper – imitate the talloc() the binary finishes   */
/*--------------------------------------------------------------------*/
static void *talloc(size_t len, const uint8_t *buf)
{
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/*--------------------------------------------------------------------*/
/* 2.  custom nonce function – exact clone of the assembly supplied   */
/*--------------------------------------------------------------------*/
static int custom_nonce32(unsigned char *nonce32,
                          const unsigned char *msg32,
                          const unsigned char *key32,
                          const void *algo16,
                          void *data,
                          unsigned int attempt)
{
    (void)algo16; (void)data;
    /* only deterministic – if lib ever asks again we abort */
    if (attempt) return 0;

    /* nonce[0..15] = key32[0..15] */
    memcpy(nonce32,          key32, 16);
    /* nonce[16..31] = msg32[0..15] */
    memcpy(nonce32 + 16,     msg32, 16);

    return 1;            /* identical ‘mov eax,1 ; ret’ semantics */
}

/*--------------------------------------------------------------------*/
int main(void)
/*--------------------------------------------------------------------*/
{
    /*---------------------------  RNG / privkey  ---------------------------*/
    unsigned char priv[32];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur || fread(priv, 1, 32, ur) != 32) {
        perror("/dev/urandom"); return EXIT_FAILURE;
    }
    fclose(ur);

    /*---------------------------  Context  ---------------------------------*/
    secp256k1_context *ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /*---------------------------  Message digests  -------------------------*/
    static const char quote1[] = "Lord, grant me the strength to accept the things I cannot change; Courage to change the things I can; And wisdom to know the difference.";
    static const char quote2[] = "Wherever There Is Light, There Are Always Shadows";

    unsigned char msg1[32], msg2[32];
    assert(strlen(quote1) == 136);
    assert(strlen(quote2) == 49);
    SHA256((const unsigned char *)quote1, strlen(quote1), msg1);
    SHA256((const unsigned char *)quote2, strlen(quote2), msg2);

    /*---------------------------  Signatures  ------------------------------*/
    secp256k1_ecdsa_signature sig1, sig2;

    if (!secp256k1_ecdsa_sign(ctx, &sig1, msg1, priv,
                              custom_nonce32, NULL) ||
        !secp256k1_ecdsa_sign(ctx, &sig2, msg2, priv,
                              custom_nonce32, NULL))
    {
        fprintf(stderr, "ECDSA sign failed\n");
        return EXIT_FAILURE;
    }

    /*---------------------------  Serialise sigs ---------------------------*/
    unsigned char sig1_raw[64], sig2_raw[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, sig1_raw, &sig1);
    secp256k1_ecdsa_signature_serialize_compact(ctx, sig2_raw, &sig2);

    /*---------------------------  Public key & verify ----------------------*/
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) {
        fprintf(stderr, "Pubkey create failed\n");
        return EXIT_FAILURE;
    }
    if (!secp256k1_ecdsa_verify(ctx, &sig1, msg1, &pub) ||
        !secp256k1_ecdsa_verify(ctx, &sig2, msg2, &pub))
    {
        fprintf(stderr, "Signature self-verify failed\n");
        return EXIT_FAILURE;
    }

    /* Serialise pubkey – flags=2 => uncompressed, length 65               */
    unsigned char pub_ser[65];
    size_t publen = 65;
    secp256k1_ec_pubkey_serialize(ctx, pub_ser, &publen, &pub,
                                  SECP256K1_EC_UNCOMPRESSED);

    /*---------------------------  Flag plaintext ---------------------------*/
    unsigned char plain[32];
    memset(plain, 0, sizeof plain);
    const char flag[] = "CTF{sample_flag_here}";
    memcpy(plain, flag, sizeof flag - 1);      /* 21 bytes                 */
    memset(plain + sizeof flag - 1, 0x0b, 11); /* padding bytes            */

    /*---------------------------  AES-128-CBC ------------------------------*/
    unsigned char sha_priv[32], aes_key[16], iv[16];
    SHA256(priv, 32, sha_priv);
    memcpy(aes_key, sha_priv, 16);   /* key  = SHA256(priv)[0..15]      */
    memcpy(iv,      priv,     16);   /* IV   = priv[0..15]              */

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    int len1 = 0, len2 = 0;
    unsigned char cipher[64];       /* plenty – 32-byte plain + padding */

    EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, aes_key, iv);
    EVP_CIPHER_CTX_set_padding(ectx, 1);
    EVP_EncryptUpdate(ectx, cipher, &len1, plain, 32);
    EVP_EncryptFinal_ex(ectx, cipher + len1, &len2);
    int cipherlen = len1 + len2;
    EVP_CIPHER_CTX_free(ectx);

    /*---------------------------  Store / print with talloc ---------------*/
    talloc(sizeof(priv), priv);
    talloc(64, sig1_raw);            /* signature #1 (compact)           */
    talloc(sizeof(sig1), &sig1);
    talloc(64, sig2_raw);            /* signature #2 (compact)           */
    talloc(sizeof(sig2), &sig2);
    talloc(32, cipher);              /* AES-128-CBC ciphertext (first 32)*/

    /*---------------------------  Clean up ---------------------------------*/
    secp256k1_context_destroy(ctx);
    return 0;
}

