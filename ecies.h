#ifndef CURVE25519_ECIES
#define CURVE25519_ECIES
int ecies_init();
size_t ecies_encrypt(unsigned char *pk, size_t pklen,
				  unsigned char *data, size_t datalen,
				  unsigned char **out);
size_t ecies_decrypt(unsigned char *pk, size_t pklen,
				  unsigned char *data, size_t datalen,
				  unsigned char **out);
void ecies_cleanup();
#endif
