#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#define PRINT_ERR(fmt, ...) fprintf(stderr, "%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__);
#define panic(label) ret = 0; goto label;
static EC_GROUP *curve;
static EC_POINT *g;
static BIGNUM *order;
static BN_CTX *ctx;
static EVP_CIPHER_CTX *cipher;

static size_t 
aes_encrypt(unsigned char *key, unsigned char *data,
		size_t datalen, unsigned char **out)
{
	size_t ret;
	if(!cipher)
		cipher = EVP_CIPHER_CTX_new();
	unsigned char iv[16];
	RAND_bytes(iv, 16);
	EVP_EncryptInit_ex(cipher, EVP_aes_256_cbc(), 0, key, iv);
	unsigned char *aes_out = OPENSSL_malloc(datalen + 15);
	size_t aes_outlen = 0;
	int block_len = 0;
	if(!EVP_EncryptUpdate(cipher, aes_out, &block_len, data, datalen))
	{
		panic(aes_err);
	}
	aes_outlen += block_len;
	if(!EVP_EncryptFinal_ex(cipher, aes_out+block_len, &block_len))
	{
		panic(aes_err);
	}
	aes_outlen += block_len;
	
	*out = malloc(aes_outlen+16);
	memcpy(*out, iv, 16);
	memcpy(*out+16, aes_out, aes_outlen);
	ret = aes_outlen+16;
aes_err:
	free(aes_out);
	return ret;
}

static size_t
aes_decrypt(unsigned char *key, unsigned char *data, size_t datalen, unsigned char **ret)
{

    size_t retlen = 0;
	if(!cipher)
    	cipher = EVP_CIPHER_CTX_new();
	unsigned char iv[16];
    memcpy(iv, data, 16);
    data+=16;
    EVP_DecryptInit_ex(cipher, EVP_aes_256_cbc(), 0, key, iv);
    *ret = OPENSSL_malloc(datalen + 15);
    int block_len = 0;
    EVP_DecryptUpdate(cipher, *ret, &block_len, data, datalen-16);
    retlen += block_len;
    EVP_DecryptFinal_ex(cipher, *ret+block_len, &block_len);
    retlen += block_len;

    return retlen;
}
int ecies_init()
{
	ctx = BN_CTX_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *gx = BN_new();
	BIGNUM *gy = BN_new();
	order = BN_new();
	BIGNUM *cofactor = BN_new();
	EC_GROUP *ed25519 = EC_GROUP_new(EC_GFp_simple_method());
	g = EC_POINT_new(ed25519);
	BN_hex2bn(&p, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
	BN_hex2bn(&a, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144");
	BN_hex2bn(&b, "7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864");
	BN_hex2bn(&gx, "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a");
	BN_hex2bn(&gy, "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9");
	BN_hex2bn(&order, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
	BN_set_word(cofactor, 8);

	EC_GROUP_set_curve_GFp(ed25519, p, a, b, ctx);
	EC_POINT_set_affine_coordinates_GFp(ed25519, g, gx, gy, ctx);
	EC_GROUP_set_generator(ed25519, g, order, cofactor);
	curve = ed25519;
	cipher = EVP_CIPHER_CTX_new();
	BN_free(cofactor);
	BN_free(gy);
	BN_free(gx);
	BN_free(p);
	BN_free(b);
	BN_free(a);
	return 1;
}

void ecies_cleanup()
{
	EC_POINT_free(g);
	BN_free(order);
	BN_CTX_free(ctx);
	EC_GROUP_free(curve);
	EVP_CIPHER_CTX_free(cipher);
}

size_t
ecies_encrypt(unsigned char *pk, size_t pklen,
		unsigned char *data, size_t datalen,
		unsigned char **out)
{
	size_t ret = 0;
	EC_POINT *pk_point = EC_POINT_new(curve);
	EC_POINT_oct2point(curve, pk_point, pk, pklen, ctx);

	BIGNUM *k = BN_new();
	BN_rand_range(k, order);

	EC_POINT *gk = EC_POINT_new(curve);
	EC_POINT_mul(curve, gk, k, 0, 0, ctx);
	uint32_t gk_buflen = EC_POINT_point2oct(curve, gk,
			POINT_CONVERSION_UNCOMPRESSED, 0, 0, 0);
	unsigned char *gk_buf = malloc(gk_buflen);
	EC_POINT *kpk = EC_POINT_new(curve);
	EC_POINT_point2oct(curve, gk,
			POINT_CONVERSION_UNCOMPRESSED, gk_buf, gk_buflen, ctx);


	EC_POINT_mul(curve, kpk, 0, pk_point, k, ctx);

	size_t kpk_buflen = EC_POINT_point2oct(curve, kpk,
			POINT_CONVERSION_UNCOMPRESSED, 0, 0, 0);
	unsigned char *kpk_buf = malloc(kpk_buflen);
	EC_POINT_point2oct(curve, kpk,
			POINT_CONVERSION_UNCOMPRESSED, kpk_buf, kpk_buflen, ctx);

	unsigned char iv[16];
	unsigned char aeskey[32];
	unsigned char mackey[8];
	unsigned char derived[40] = {0};
	RAND_bytes(iv, 16);
	PKCS5_PBKDF2_HMAC((char*)kpk_buf, kpk_buflen, 0, 0, 0, EVP_sha256(), 40, derived);
	memcpy(aeskey, derived, 32);
	memcpy(mackey, derived+32, 8);
	
	unsigned char *aes_out;
	uint32_t aes_outlen = aes_encrypt(aeskey, data, datalen, &aes_out);
	
	unsigned char *mac = malloc(SHA256_DIGEST_LENGTH);
	uint32_t maclen;
	HMAC(EVP_sha256(), mackey, 8, aes_out, aes_outlen, mac, &maclen);
	
	*out = malloc(4+gk_buflen+4+aes_outlen+4+maclen);
	uint32_t gk_buflen_be = htonl(gk_buflen);
	uint32_t aes_outlen_be = htonl(aes_outlen);
	uint32_t maclen_be = htonl(maclen);
	memcpy(*out, &gk_buflen_be, 4);
	memcpy(*out+4, gk_buf, gk_buflen);
	memcpy(*out+4+gk_buflen, &aes_outlen_be, 4);
	memcpy(*out+4+gk_buflen+4, aes_out, aes_outlen);
	memcpy(*out+4+gk_buflen+4+aes_outlen, &maclen_be, 4);
	memcpy(*out+4+gk_buflen+4+aes_outlen+4, mac, maclen);
	ret = 4+gk_buflen+4+aes_outlen+4+maclen;

	free(mac);
	free(aes_out);
	free(kpk_buf);
	EC_POINT_free(kpk);
	EC_POINT_free(gk);
	BN_free(k);
	EC_POINT_free(pk_point);
	free(gk_buf);
	return ret;
}

size_t ecies_decrypt(unsigned char *sk, size_t sklen,
				  unsigned char *data, size_t datalen,
				  unsigned char **out)
{
	BIGNUM *sk_bn = BN_new();
	BN_bin2bn(sk, sklen, sk_bn);
	EC_POINT *C1 = EC_POINT_new(curve);
	EC_POINT *C2 = EC_POINT_new(curve);

	uint32_t c1len_be;
	memcpy(&c1len_be, data, 4);
	data+=4;
	uint32_t c1buf_len = ntohl(c1len_be);
	unsigned char c1buf[c1buf_len];
	memcpy(c1buf, data, c1buf_len);
	data+=c1buf_len;
	EC_POINT_oct2point(curve, C1, 
			c1buf, c1buf_len, ctx);
	EC_POINT *pubkey = EC_POINT_new(curve);
	EC_POINT_mul(curve, C2, 0, C1, sk_bn, ctx);
	size_t c2buf_len = EC_POINT_point2oct(curve, C2, 
			POINT_CONVERSION_UNCOMPRESSED, 0, 0, 0);
	unsigned char c2buf[c2buf_len];
	EC_POINT_point2oct(curve, C2,
			POINT_CONVERSION_UNCOMPRESSED, c2buf, c2buf_len, ctx);

	uint32_t aeslen_be;
	memcpy(&aeslen_be, data, 4);
	data+=4;
	uint32_t aesbuf_len = ntohl(aeslen_be);
	unsigned char aes_in[aesbuf_len];
	memcpy(aes_in, data, aesbuf_len);
	data+=aesbuf_len;

	uint32_t maclen_be;
	memcpy(&maclen_be, data, 4);
	data+=4;
	uint32_t mac_in_len = ntohl(maclen_be);
	unsigned char mac_in[mac_in_len];
	memcpy(mac_in, data, mac_in_len);
	data+=mac_in_len;

	if(datalen != 4+c1buf_len+4+aesbuf_len+4+mac_in_len)
	{
		PRINT_ERR("MAC length mismatch");
		return 0;
	}
	unsigned char derived[40];
	PKCS5_PBKDF2_HMAC((char*)c2buf, c2buf_len, 0, 0, 0, EVP_sha256(), 40, derived);
	unsigned char aeskey[32];
	unsigned char mackey[8];
	memcpy(aeskey, derived, 32);
	memcpy(mackey, derived+32, 8);

	unsigned char hmac[SHA256_DIGEST_LENGTH];
	unsigned int hmac_len;
	if(!HMAC(EVP_sha256(), mackey, 8, aes_in, aesbuf_len, hmac, &hmac_len))
	{
		PRINT_ERR("MAC creation error\n");
		return 0;
	}

	if(mac_in_len != hmac_len || (memcmp(hmac, mac_in, hmac_len) != 0))
	{
		PRINT_ERR("MAC mismatch\n");
		fflush(stdout);
		return 0;
	}

	unsigned char *aes_out;
	size_t aes_outlen = aes_decrypt(aeskey, aes_in, aesbuf_len, &aes_out);
	*out = aes_out;

	EC_POINT_free(pubkey);
	EC_POINT_free(C2);
	EC_POINT_free(C1);
	BN_clear_free(sk_bn);
	return aes_outlen;

}

#ifdef DEBUG
int main()
{
	ecies_init();
	unsigned char in[4] = {0xde, 0xad, 0xbe, 0xef};
	unsigned char *out;
	size_t outlen = 0;
	size_t i;
	{
		BIGNUM *priv = BN_new();
		BN_rand_range(priv, order);
		EC_POINT *pub = EC_POINT_new(curve);
		EC_POINT_mul(curve, pub, priv, 0, 0, 0);
		size_t publen = EC_POINT_point2oct(curve, pub, 
				POINT_CONVERSION_UNCOMPRESSED, 0, 0, 0);
		unsigned char pub_buf[publen];
		EC_POINT_point2oct(curve, pub,
				POINT_CONVERSION_UNCOMPRESSED, pub_buf, publen, 0);
		outlen = ecies_encrypt(pub_buf, publen, in, 4, &out);
		for(i=0; i<outlen; i++)
		{
			printf("%02x", out[i]);
		}
		printf("\n");
		unsigned char *plain_out;
		unsigned char privbuf[BN_num_bytes(priv)];
		BN_bn2bin(priv, privbuf);
		size_t plain_outlen = ecies_decrypt(privbuf, BN_num_bytes(priv), out, outlen, &plain_out);
		puts("------------------");
		for(i=0; i<plain_outlen; i++)
			printf("%02x", plain_out[i]);
		EC_POINT_free(pub);
		free(out);
		free(plain_out);
		BN_free(priv);
	}
	ecies_cleanup();
	return 0;
}
#endif
