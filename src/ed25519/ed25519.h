#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
	int crypto_sign_keypair_from_private(unsigned char *pk, unsigned char *sk);
	int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm,
						 unsigned long long smlen, const unsigned char *pk);
	int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
					unsigned long long mlen, const unsigned char *sk);
	int crypto_sign_hdk(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                    					unsigned long long mlen, const unsigned char *sk);
	int crypto_sign_verify(const unsigned char *signature, const unsigned char *message,
						   size_t message_len, const unsigned char *public_key);
	int public_key_add(unsigned char *sum, unsigned char *pk, unsigned char *tw);
	int private_keys_add(unsigned char *sum, unsigned char *pk, unsigned char *tw);
	int compare_with_safemask(unsigned char *num);
	int safe_modL(unsigned char *num);
	int modL(unsigned char *num);

#ifdef __cplusplus
}
#endif

#endif
