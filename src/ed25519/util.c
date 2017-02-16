#include "ed25519.h"
#include "fe.h"
#include "ge.h"
#include "sc.h"

int private_keys_add(unsigned char *sum, unsigned char *pk, unsigned char *tw)
{
    fe a;
    fe b;
    fe s;

    fe_0(a);
    fe_0(b);
    fe_0(s);

    fe_frombytes(a, pk);
    fe_frombytes(b, tw);
    fe_add(s, a, b);
    fe_tobytes(sum, s);

    return 0;
}

int public_key_add(unsigned char *sum, unsigned char *pk, unsigned char *tw)
{
    ge_p3 P;
    ge_p3 k2;
    ge_cached Q;
    ge_p1p1 R;
    ge_p2 R_p2;

    ge_frombytes_negate_vartime(&P,pk);
    ge_frombytes_negate_vartime(&k2,tw);
    ge_p3_to_cached(&Q, &k2);
    ge_add(&R, &P, &Q);
    ge_p1p1_to_p2(&R_p2, &R);
    ge_tobytes(sum, &R_p2);
    sum[31] ^= 0x80;
    return 0;
}

// Compare num with SafeKeyMask
// most significant byte last
// return  1 -- num > SafeKeyMask
// return -1 -- num < SafeKeyMask
// return  0 -- num = SafeKeyMask
int compare_with_safemask(unsigned char *num)
{
    unsigned char safe_mask[32] = {0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
    int i;

    for(i =31; i>=0; --i) {
        if(num[i] == safe_mask[i]) continue;
        if(num[i] > safe_mask[i]) return 1;
        return -1;
    }
    return 0;
}

int modL(unsigned char *num)
{
    unsigned char s[64];
    int i;

    for(i=0;i<32;++i) s[i] = num[i];
    for(i=32;i<64;++i) s[i] = 0;

    sc_reduce(s);

    for(i=0;i<32;++i) num[i] = s[i];

    return 0;
}

int safe_modL(unsigned char *num)
{
    if(compare_with_safemask(num) == 1) modL(num);

    return 0;
}