#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#define MESSAGE_LEN 32
#define BASE58_LEN 35 // maximum bitcoin address length 

static const char *b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
  if (EC_POINT_mul(group, pub, prv, NULL, NULL, ctx) != 1)
    error("Unable to perform elliptic curve multiplication\n");

  if (EC_KEY_set_public_key(ec_key, pub) != 1) 
    error("Unable to set public key\n");

  /* Release memory */
  EC_POINT_free(pub);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  BN_clear_free(prv);

  return ec_key;
}

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

/* return (sha256(payload)) [first n bytes] */
unsigned char *mbase58EncodeChecksum(const short version, const unsigned char *payload, int size_payload, int bytes_return) {
  // Create a char array to fit both version number + payload
  int size_msg = sizeof(char) * 2  + sizeof(char) * size_payload;
  unsigned char *msg = malloc(size_msg);

  // prepend version number
  int i = 0;
  if (version == 0) {
    while (i <= 2) 
        msg[i++] = '0';
  }
  int j = 0;
  // Concantenate payload to version number
  while (i <= size_payload) 
    msg[i++] = payload[j++];

  unsigned int size_midresult; // size of intermediate result
  unsigned char *midresult= NULL;
  unsigned char *result = malloc(sizeof(char) * 4);

  // Double SHA 256
  digest_message(EVP_sha256, msg, size_msg, &midresult, &size_midresult); 
  digest_message(EVP_sha256, midresult, size_midresult, &midresult, &size_midresult); 
  // return first four bytes

  for (int i = 0; i < bytes_return; i++) 
    result[i] = midresult[i];
  free(msg);
  return result;
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

/* Base58 Encode msg. Takes message, message length and returns the base58 encoded message. 
   offset is the offset of from where the returned char* has real data 
*/
unsigned char *mb58Encode(const unsigned char *msg, int msg_len, int *offset) {
  // create context for BIGNUMBER operations
  BN_CTX *ctx = NULL;

  if ((ctx = BN_CTX_new()) == NULL) {
    printf("Unable to to create BN CTX\n");
    exit(1);
  }

  BN_CTX_start(ctx);
  // Create BIG NUMBER variables
  BIGNUM *bn58 = NULL;
  BIGNUM *bn0 = NULL;
  BIGNUM *bn_msg = NULL;
  BIGNUM *bn_dv = NULL;
  BIGNUM *rem = NULL;
  BIGNUM *temp = NULL;

  // these binary numbers will be converted into Openssl Big Number format
  const unsigned char bin58 = 58;

  if (!(bn58 = BN_new()) || !(bn0 = BN_new()) || !(bn_msg = BN_new()) || !(bn_dv = BN_new()) || !(rem = BN_new()) || !(temp = BN_new()))
    printf("Unable to create big numbers for b58 encode");

  // Convert 58, 0 and msg into Big Numbers
  BN_bin2bn(&bin58, 1, bn58);

  if (!BN_zero(bn0))
    printf("Unable to set BIGNUM 0");
  
  // Convert msg into a bignum to prepare for bignum division
  BN_bin2bn(msg, msg_len, bn_dv);

  char unsigned bin_rem = 0; // Create remainder variable as a char

  unsigned char *str = malloc(sizeof(char) * BASE58_LEN); // output string

  int i = BASE58_LEN -1;

  str[i--] = '\0'; // create null terminated string

  // while bn_msg as x > 0  divide x by 58
  while (BN_cmp(bn_dv, bn0) > 0) {
    if (!BN_copy(temp, bn_dv))
      error("unable to copy bn_dv to temp");

     // printf("%lu / %lu = ", *temp->d, *bn58->d);
    if (!BN_div(bn_dv, rem, temp, bn58, ctx))
      error("Unable to perform BIGNUM division");

     // printf("bn_dv %lu rem: %lu\n", *bn_dv->d, *rem->d);

    BN_bn2bin(rem, &bin_rem); 

    str[i--] = b58[bin_rem]; 
  }

  // Replace leading zeros in msg hash with the b58 representation of a zero
  int yes = 0; 
  do {
    str[i] = b58[0];
    yes = (*msg && *msg++ == '0');
    if (yes)
      printf("has leading zero\n");
  } while (yes && i--); 

  // return offset
  *offset= i;

  // FREE BIG NUMBER variables
  BN_free(bn58);
  BN_free(bn0);
  BN_free(bn_msg);
  BN_free(bn_dv);
  BN_free(rem);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return str;
}

/* Find position of character in string str. Searches up to len length or when \0 is encountered */
int strpos(const char c, const char *str, int len) {
  int pos = 0;
  while (*(str + pos)) {
   if ( *(str + pos) == c) 
     return pos;
   pos++;
  }
  return -1;
}
    
/* Decode base58 string into decimal */
// TODO
unsigned char *mbase58Decode(const char *msg, int msg_sz, int *ret_len) {
  char b10[] = "0123456789";   

  BN_CTX *ctx = NULL;
  if ((ctx = BN_CTX_new()) == NULL) {
    printf("Unable to to create BN CTX\n");
    exit(1);
  }
  BN_CTX_start(ctx);
  
  BIGNUM *total = BN_new();
  BIGNUM *temp = BN_new();

  unsigned char *str = calloc(msg_sz, sizeof(char));
  
  for (int i = 0; i < msg_sz; i++) {
    const char *c =  msg + i;
    if (*c) {
      double num = (double) strpos(*c, b58, 58);
      double exponent = (double) (msg_sz - 1 - i);
      int mult_by = pow(58, exponent);
    }
  }
  
  BN_free(total);
  BN_free(temp);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return str;
}

