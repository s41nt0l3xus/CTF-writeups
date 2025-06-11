/*
 *  $ gcc -o convert convert.c libsecp256k1.a
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <unistd.h>
#include <secp256k1.h>

int main(int argc, char **argv)
{
  secp256k1_context *ctx =
    secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (!ctx)
  {
    fprintf(stderr, "Failed to create secp256k1 context\n");
    return EXIT_FAILURE;
  }

  while (true)
  {
    secp256k1_ecdsa_signature sig;
    if (read(STDIN_FILENO, &sig, sizeof(sig)) != sizeof(sig))
    {
      perror("read");
      return EXIT_FAILURE;
    }

    uint8_t compact[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &sig);
    if (write(STDOUT_FILENO, compact, sizeof(compact)) != sizeof(compact))
    {
      perror("write");
      return EXIT_FAILURE;
    }
  }
}
