#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#define MESSAGE_LEN 32

void error(char *msg) {
  printf("Error: %s\n", msg);
  exit(1);
}

/* 256 bit string */
void random_256bit_string(unsigned char msg[32]) {
  int fd;
  int n_read;

  fd = open("/dev/urandom", O_RDONLY, 0);
  // TODO: To match Bitcoin elliptic curve key gen ensure msg bits are < (1.158 * 10^77) -1, which is slightly less than 2^256

  if ((n_read = read(fd, msg, MESSAGE_LEN)) == -1) { 
    printf("Error getting random values\n");
    exit(1);
  }
  close(fd);
}

/* Generate A public Key from a 256 bit private key */
EC_KEY *gen_pub_key_from_priv_key(unsigned char msg[32]) {
  // structures needed for ECC
  EC_KEY *ec_key = 0;
  BIGNUM *prv = 0;
  BN_CTX *ctx = 0;
  const EC_GROUP *group = 0;
  EC_POINT *pub = 0;

  // Transform char [] binary to BN and use as private key
  prv = BN_new();
  BN_bin2bn(msg, 32, prv);
  ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  EC_KEY_set_private_key(ec_key, prv);

  // Generate pub key from priv key
  // Create BN context to efficiently allocate Big Numbers
  if ((ctx = BN_CTX_new()) == NULL) {
    printf("Unable to to create BN CTX\n");
    exit(1);
  }
  BN_CTX_start(ctx);
  
  group = EC_KEY_get0_group(ec_key);
  
  if (!(pub = EC_POINT_new(group))) {
    printf("Unable to create EC_POINT (pub key) \n");
    exit(1);
  }
  
  // multiply private key * Generator Constant to get a point on EC 
  EC_POINT_mul(group, pub, prv, NULL, NULL, ctx);
  EC_KEY_set_public_key(ec_key, pub);

  /* Release memory */
  EC_POINT_free(pub);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  BN_clear_free(prv);

  return ec_key;
}

/* Generate a private and public key pair */
/*
void init_priv_pub_key_pair(void **ec_key) {
    if (!ec_key) 
    printf("ec_key NULL 1\n");
  
  *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  EC_KEY_generate_key(*ec_key);
  if (!ec_key) 
    printf("ec_key NULL 2\n");
}*/

EC_KEY *init_priv_pub_key_pair() {
  EC_KEY *ec_key;
  ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  EC_KEY_generate_key(ec_key);
  if (!ec_key) 
    printf("ec_key NULL 2\n");
  return ec_key;
}

/* Get private key from initialized EC_KEY object */
const BIGNUM *get_private_key(EC_KEY *ec_key) {
  return EC_KEY_get0_private_key(ec_key);
}

/* Get public key from initialized EC_KEY object */
const EC_POINT *get_public_key(EC_KEY *ec_key) {
  return EC_KEY_get0_public_key(ec_key);
}

/* Get Elliptic Curve Group */
const EC_GROUP *get_group(EC_KEY *ec_key) {
  return EC_KEY_get0_group(ec_key);
}

/* Convert public key points to hexadecimal */
char *pub_key_hex(EC_KEY *ec_key) {
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  return EC_POINT_point2hex(get_group(ec_key), get_public_key(ec_key), form, NULL);
}

void digest_message(const EVP_MD* (*hash)(void), const unsigned char *msg, size_t msg_len, unsigned char **digest, unsigned int *digest_len) {
  EVP_MD_CTX *mdctx;
if ((mdctx = EVP_MD_CTX_create()) == NULL)
    error("EVP_MD_CTX_create()");

  if (EVP_DigestInit_ex(mdctx, hash(), NULL) != 1) 
    error("initializing msg context by initializing SHA256 algorithm");

  if (EVP_DigestUpdate(mdctx, msg, msg_len) != 1)
    error("Message Digest Update");
  
  if ((*digest = (unsigned char *) OPENSSL_malloc(EVP_MD_size(hash()))) == NULL)
    error("Unable to allocate space for message digest");

  if (EVP_DigestFinal_ex(mdctx, *digest, digest_len) != 1)
    error("Unable to complete digest");

  EVP_MD_CTX_destroy(mdctx);
}

/* Generate Address from Public Key & allocate memory */
// A = RIPEMID(160(SHA256(K)))
unsigned char *mget_address(EC_KEY *ec_key, unsigned int *size_digest) {
  // Convert point to BN
  const EC_GROUP *group = NULL; 
  EC_POINT *pub = NULL; 
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  BIGNUM *bn_pub = NULL;
  BN_CTX *ctx = NULL; // Not planning to use BN context for dealing with multiple big nubmers
  int size_bin_pub; // size of binary public key
  unsigned char *sha256_digest = NULL;
  unsigned char *ripemd160_digest = NULL;
  unsigned char *bin_pub = NULL; // bin of pub key
  if ((group = get_group(ec_key)) == NULL) 
    error("get_group()");
  if ((pub = get_public_key(ec_key)) == NULL) 
    error("get_public_key()");
  if ((bn_pub = EC_POINT_point2bn(group, pub, form, bn_pub, ctx)) == NULL) 
    error("Unable to convert public key point to big number");
  // bn to bin
  bin_pub = malloc(BN_num_bytes(bn_pub));
  BN_bn2bin(bn_pub, bin_pub);
  if ((size_bin_pub = BN_bn2bin(bn_pub, bin_pub)) == 0) 
    error("size of binary public key is 0, that sounds wrong!");
  // Calculate Address
  digest_message(EVP_sha256, bin_pub, size_bin_pub, &sha256_digest, size_digest); 
  digest_message(EVP_ripemd160, sha256_digest, size_bin_pub, &ripemd160_digest, size_digest); 
 
   // EVP_sha256
  EC_POINT_free(pub);
  free(bin_pub);

  return ripemd160_digest;
}
