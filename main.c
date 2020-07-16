/* hashes main
    -ladvapi32

   @: YX Hao
   #: 20200616
*/

#include <stdlib.h>
#include <stdio.h>
#include <io.h>

#include "win-hashes.h"

typedef struct _ALG_MAP {
    char *alg;
    ALG_ID id;
    int len;
} ALG_MAP;

#define ALGIDMAP(s,n) #s, CALG_ ## s, n
ALG_MAP ALGs[] = {
    ALGIDMAP(MD2, 16),
    ALGIDMAP(MD4, 16),
    ALGIDMAP(MD5, 16),
    ALGIDMAP(SHA, 20),
    ALGIDMAP(SHA1, 20),
    ALGIDMAP(SHA_256, 32),
    ALGIDMAP(SHA_384, 48),
    ALGIDMAP(SHA_512, 64)
};
#undef ALGIDMAP

ALG_ID get_alg_id_and_len(char *alg, int *len) {
    int i, n;

    n = sizeof(ALGs) / sizeof(ALG_MAP);
    for (i = 0; i < n; i++) {
        if (stricmp(alg, ALGs[i].alg) == 0) {
            *len = ALGs[i].len;
            return ALGs[i].id;
        }
    }

    return -1;
}


/*
To hash large files, the function reads manageable chunk in rounds.
The size of this buffer is as follows:
0 = 256 KB, 1 = 512 KB, 2 = 1.00 MB, 3 = 2.00 MB, 4 = 4.00 MB,
5 = 8.00 MB, 6 = 16.0 MB, 7 = 32.0 MB, 8 = 64.0 MB
2^(18+n)
*/
#define MemBlockSize 1 << (18 + 2)

void * hash_file(ALG_ID id, char *file, unsigned char *digest) {
    FILE *f;
    unsigned char *buff;
    size_t n;
    CRYPT_CTX ctx = {0};

    f = fopen(file, "rb");
    if (f == NULL) {
        fprintf(stderr, "Can't open file: %s\n", file);
        return NULL;
    }
    buff = malloc(MemBlockSize);
    if (f == NULL) {
        fprintf(stderr, "Err: malloc\n");
        return NULL;
    }
    hash_init(id, &ctx);
    while (!feof(f)) {
        n = fread(buff, 1, MemBlockSize, f);
        hash_update(&ctx, buff, n);
    }
    free(buff);
    fclose(f);
    hash_final(&ctx, digest);
    return digest;
}


void show_digest (unsigned char dig[], int n) {
    int i;
    for (i = 0; i < n; i++) printf("%02X", dig[i]);
}

void show_help(char *app) {
    int i, n;

    printf("Tiny Windows Hashes Calculator v0.2.0 - #2020 @lifenjoiner\n");
    printf("Usage: %s <-opt> [...] <file|-t string>\n", app);
    printf("opt (case insensitive):\n");

    n = sizeof(ALGs) / sizeof(ALG_MAP);
    for (i = 0; i < n; i++) {
        printf("  %s\n", ALGs[i].alg);
    }
}


int main(int argc, char **argv) {
    int i, n;
    ALG_ID id;
    char *task;
    CRYPT_CTX ctx = {0};
    unsigned char *digest, *result;
    int len;

    if (argc < 3) {
        show_help(argv[0]);
        return 1;
    }

    task = argv[argc - 1];
    if (argc > 3 && stricmp(argv[argc - 2], "-t") == 0) {
        // -t
        n = argc - 2;
    }
    else if (access(task, 0)) {
        fprintf(stderr, "file doesn't exist: %s\n", task);
        return 1;
    }
    else if (access(task, 4)) {
        fprintf(stderr, "file can't be read: %s\n", task);
        return 1;
    }
    else {
        n = argc - 1;
    }

    for (i = 1; i < n; i++) {
        if (!argv[i]) continue; // ""
        id = get_alg_id_and_len(argv[i] + 1, &len);
        if (id == -1) {
            fprintf(stderr, "Unknown: %s\n", argv[i]);
            show_help(argv[0]);
            return 1;
        }
        digest = calloc(len, 1);
        if (digest == NULL) {
            fprintf(stderr, "Err: calloc\n");
            return 1;
        }
        printf("%s: ", argv[i] + 1);
        if (n == argc - 1) {
            result = hash_file(id, task, digest);
        }
        else {
            result = hash_buffer(id, task, strlen(task), digest);
        }
        if (result) {
            show_digest(digest, len);
            printf("\n");
        }
        free(digest);
    }

    return 0;
}
