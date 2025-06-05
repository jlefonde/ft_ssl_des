#include "ssl.h"

// PBKDF2 (P, S, c, dkLen)

// Options:        PRF        underlying pseudorandom function (hLen
//                             denotes the length in octets of the
//                             pseudorandom function output)

// Input:          P          password, an octet string
//                 S          salt, an octet string
//                 c          iteration count, a positive integer
//                 dkLen      intended length in octets of the derived
//                             key, a positive integer, at most
//                             (2^32 - 1) * hLen

// Output:         DK         derived key, a dkLen-octet string

// Steps:

//     1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
//         stop.

//     2. Let l be the number of hLen-octet blocks in the derived key,
//         rounding up, and let r be the number of octets in the last
//         block:

//                 l = CEIL (dkLen / hLen) ,
//                 r = dkLen - (l - 1) * hLen .

//         Here, CEIL (x) is the "ceiling" function, i.e. the smallest
//         integer greater than, or equal to, x.

//     3. For each block of the derived key apply the function F defined
//         below to the password P, the salt S, the iteration count c, and
//         the block index to compute the block:

//                 T_1 = F (P, S, c, 1) ,
//                 T_2 = F (P, S, c, 2) ,
//                 ...
//                 T_l = F (P, S, c, l) ,

//         where the function F is defined as the exclusive-or sum of the
//         first c iterates of the underlying pseudorandom function PRF
//         applied to the password P and the concatenation of the salt S
//         and the block index i:
//                 F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c

//         where

//                 U_1 = PRF (P, S || INT (i)) ,
//                 U_2 = PRF (P, U_1) ,
//                 ...
//                 U_c = PRF (P, U_{c-1}) .

//         Here, INT (i) is a four-octet encoding of the integer i, most
//         significant octet first.

//     4. Concatenate the blocks and extract the first dkLen octets to
//         produce a derived key DK:

//                 DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

//     5. Output the derived key DK.

// Note. The construction of the function F follows a "belt-and-
// suspenders" approach. The iterates U_i are computed recursively to
// remove a degree of parallelism from an opponent; they are exclusive-
// ored together to reduce concerns about the recursion degenerating
// into a small set of values.

uint8_t *F(void *(*prf)(uint8_t *key, size_t key_len, uint8_t *msg, size_t msg_len),
           size_t hLen, uint8_t *password, size_t password_len,
           uint8_t *salt, size_t salt_len, size_t c, size_t i)
{
    uint8_t * prf_res = prf(password, password_len, salt, salt_len);
    return (prf_res);
}

uint8_t *pbkdf2(
    void *(*prf)(uint8_t *key, size_t key_len, uint8_t *msg, size_t msg_len),
    size_t hLen,
    uint8_t *password,
    size_t password_len, 
    uint8_t *salt,
    size_t salt_len, 
    size_t c,
    size_t dkLen)
{
    if (dkLen > (4294967295 * hLen))
    {
        print_error("pbkdf2", "Derived key too long", NULL);
        return (NULL);
    }

    size_t l = ceil(dkLen / hLen);
    size_t r = dkLen - (l - 1) * hLen;

    uint8_t **t = malloc(l * sizeof(uint8_t *));
    for (int i = 1; i <= l; i++)
        t[i - 1] = F(prf, hLen, password, password_len, salt, salt_len, c, i);

    for (int i = 0; i < l; i++)
    {
        printf("t[%d]: ", i);
        for (int j = 0; j < hLen; j++)
            printf("%02X", t[i][j]);
        printf("\n");
    }
}
