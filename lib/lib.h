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
#define BASE58_LEN 35 // maximum bitcoin address length 

static const char *b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void error(char *msg) {
  printf("Error: %s\n", msg);
  exit(1);
}

/* 
 * Generate cryptographically secure random 256 bit string 
 * Accept a pointer to a char buffer large enough to store 256 bits
 */
void random_256bit_string(unsigned char *msg) {
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

/* Generate A public Key from a 256 bit private key
 * Accepts a pointer to a char buffer which is a 256-bit private key
 */
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

/* Create a public-key and private-key pair on the secp256k1 Elliptic curve (used by Bitcoin)
 * This returns an OpenSSL EC_KEY structure used to access the generated public/private keys
 */
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

/* Digest a Message using a given Hash function
 * hash(void) is the hash algorithm to use, 
 * msg is the message to digest,
 * msg_len is msg's length
 * digest is the address to which to save the digest
 * digest_len is the length of the digest
 *
 * */
void digest_message(const EVP_MD* (*hash)(void), const unsigned char *msg, size_t msg_len, unsigned char **digest, unsigned int *digest_len) {
  EVP_MD_CTX *mdctx;
if ((mdctx = EVP_MD_CTX_create()) == NULL)
    error("EVP_MD_CTX_create()");

  if (EVP_DigestInit_ex(mdctx, hash(), NULL) != 1) 
    error("initializing msg context by initializing hash  algorithm");

  if (EVP_DigestUpdate(mdctx, msg, msg_len) != 1)
    error("Message Digest Update");
  
  if ((*digest = (unsigned char *) OPENSSL_malloc(EVP_MD_size(hash()))) == NULL)
    error("Unable to allocate space for message digest");

  if (EVP_DigestFinal_ex(mdctx, *digest, digest_len) != 1)
    error("Unable to complete digest");

  EVP_MD_CTX_destroy(mdctx);
}

/* Returns an encoded checksum. 
 * Goal is to pass in base58 string then return a few bytes of that string to act as a checksum
 * Return: (sha256(payload)) [first n bytes]
 */
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
  unsigned char *midresult = NULL;
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

/* Generate Address from Public Key
 * The address becomes a double hash of the public key such that: A = RIPEMID(160(SHA256(K)))
 * Accepts (1) EC_KEY, (2) unsigned int, returned to the caller,
 * representing the size of the digest (Address generated) 
 * size_digest will the value set after the digest is created
 */
unsigned char *mget_address(EC_KEY *ec_key, unsigned int *size_digest) {
  // Convert point to BN
  const EC_GROUP *group = NULL; 
  const EC_POINT *pub = NULL;
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
  EC_POINT_free((void *) pub);
  free(bin_pub);

  return ripemd160_digest;
}

/* Base58 Encode msg. Takes message, message length and returns the base58 encoded message. 
 * The "offset" is needed to notify the user where in the array does the data begin.
 * In other words what address to start at.
 * This allows the ability of not having to know in advance what the length of the 
 * base58 encoded message will be.
 * if array x looks like this [NULL, NULL, value, value, value] the offset will be two 
 * for ex: printf("%s\n", x+2);
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

    str[i--] = b58[bin_rem];  // TODO: remove extra decrement
  }

  i++; // sloppy fix of extra decrement from above while loop

  // Replace leading zeros in msg hash with the b58 representation of a zero
  int yes = 0; 
  do {
    yes = (*msg && *msg++ == '0');
    if (yes) {
      str[i] = b58[0];
      printf("has leading zero\n");
    }
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
    
/* Convert a base58 string into a binary number.
 * Binary number maybe larger than can be represented by a data type.
 * Returned value is a char buffer
*/
unsigned char *mbase58Decode(const unsigned char *msg, int msg_sz, int *ret_len) {
  BN_CTX *ctx = NULL;
  if ((ctx = BN_CTX_new()) == NULL) {
    printf("Unable to to create BN CTX\n");
    exit(1);
  }
  BN_CTX_start(ctx);
  
  BIGNUM *subtotal = BN_new();
  BIGNUM *total = BN_new();
  BN_zero(total); // zero initialize total
  BIGNUM *bn_num = BN_new();
  BIGNUM *temp = BN_new();
  BIGNUM *bn58 = BN_new();
  BIGNUM *bnexp = BN_new();

  const unsigned char ch58 =  58;
  unsigned char chexp = 0; // assumes size of exponent < 255
  unsigned char *str =  NULL;
  
  // (num  * 58 ^ exp) + (num * 58 ^ exp-1) ... + (num * 58 ^ epx-n)
  for (unsigned char i = 0; i < msg_sz; i++) {
    const unsigned char *c =  msg + i;
    if (*c) {
      // Convert 58 as a char to 58 as a BIGNUMBER
      BN_bin2bn(&ch58, 1, bn58);
      chexp = (msg_sz - 1 - i);
      // convert the char exponent to a BIGNUMBER
      BN_bin2bn(&chexp, 1, bnexp);
      const unsigned char num = strpos(*c, b58, 58);
      // convert num to a temporary BIG NUM variable. 
      BN_bin2bn(&num, 1, bn_num);
      // raise 58 to exponentj
      BN_exp(temp, bn58, bnexp, ctx);
      // subtotal = num * temp 
      BN_mul(subtotal, bn_num, temp, ctx);
      //total = total + subtotal 
      BN_add(total, total, subtotal);
    }
  }
  // Allocate char const * large enough to store BIGNUMBER 
  unsigned int bytes = BN_num_bytes(total);
  str = malloc(bytes);
  // Convert BIGNUMBER total into binary: unsigned char *
  if ((*ret_len = BN_bn2bin(total, str)) == 0) 
     error ("Wrote zero bytes when converting BIGNUM total to str char *");

  
  BN_free(subtotal);
  BN_free(total);
  BN_free(temp);
  BN_free(bn_num);
  BN_free(bn58);
  BN_free(bnexp);
 
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return str;
}

/* 
 * The following functions are for a Heiarchichal Determenistic Wallet 
*/

typedef struct HDWKey {
  EC_KEY *ec_key;
  unsigned char *seed;
  unsigned char *master_chain_code;
} HDWKey;

/* Create a Seed to be used for HDwallet generation
 * Returns 33 byte char 
 * */
unsigned char *mHDW_seed_key_create(void) {
   // Create random 256 bit string 
   // 32 + 1 byte for checksum
  unsigned char *rand_seq = calloc(33, 1);
  random_256bit_string(rand_seq);
  unsigned int size_rand_seq = 33;
  unsigned char *checksum = NULL;
  unsigned int size_checksum;
 
  // checksum
  digest_message(EVP_sha256, rand_seq, size_rand_seq, &checksum, &size_checksum);
  // add first byte of checksum to msg
  rand_seq[32] = checksum[0];
  free(checksum);
  return rand_seq;
}

/* Read words from File to a char ** buffer.
 * Helper method for mnemonic function. Saves words into a char *[2048]
 */
char **mWords_from_file(char *mnemonic_words_file) {
  if (!mnemonic_words_file)
      mnemonic_words_file = "english_mnemonic.txt";

  char **words = malloc(2048 * sizeof(char*));
  if (!words) error("Unable to allocate memory for mnemonic words");
  
  FILE *stream;
  char *line = NULL;
  char *w = NULL;
  size_t len = 0;
  ssize_t read;
  int w_counter = 0;

  if ((stream = fopen(mnemonic_words_file, "r")) == NULL)
    error("Unable to open mnemonic words file"); 

  while ((read = getline(&line, &len, stream)) != -1) {
    if ((w = malloc(read)) == NULL)
        error("Unable to allocate space for word");
    words[w_counter] = w;
    line[read -1] = '\0';
    strcpy(w, line);
    w_counter++;
  }

  free(line);
  fclose(stream);
  return words; 
}

int deserialize_bits(unsigned char* buffer, int n, int bit_offset) {
    int num = 0;
    for (int i = 0; i < n; i++) {
      int byte_idx = (i + bit_offset) / 8; // or >> 3
      int bit_idx = (i + bit_offset) % 8; // or & 7
      num |= ((buffer[byte_idx] >> bit_idx) & 1) << i;
    }
    return num;
}  
/* Create mnemonic list of words, delimited by a space, used to represent a key to a deterministic wallet */
char **mHDW_key_mnemonic() {
  unsigned char *seed = mHDW_seed_key_create();
  char **word_choice = mWords_from_file(NULL);
  char **phrase = malloc(24 * sizeof(char *)); 
  int num_bits = 11;
  int bit_offset = 11;
  char *word = NULL;
  // get num from seed bits
  for (int i = 0; i < 24; i++) {
    int num = deserialize_bits(seed, num_bits, bit_offset * i); 
    word = word_choice[num];
    phrase[i] = malloc(strlen(word));
    strcpy(phrase[i], word); 
  }
  free(seed); 
  // free words array of array
  for (int i = 0; i < 2048; i++) 
      free(word_choice[i]);
  free(word_choice);
  return phrase;     
}

// Create generating seed (Master key) for HD wallet and return a string
void HDW_init(HDWKey *hdw_key) {
  hdw_key->seed = mHDW_seed_key_create();
  unsigned char *seed_digest = NULL;
  unsigned char *master_private_key = NULL;
  size_t seed_size = 33; // 264 bytes
  unsigned int size_digest = 0; // final size of digest

  digest_message(EVP_sha512, hdw_key->seed, seed_size, &seed_digest, &size_digest); 
  // set master private key to 1st 256 bits of seed digest
  master_private_key = seed_digest;
  // set master public key in EC_KEY structure
  hdw_key->ec_key = gen_pub_key_from_priv_key(master_private_key);
  // set master chain code to last 256 bits of seed digest
  hdw_key->master_chain_code = malloc(32);
  for (int i = 0; i < 32; i++)
      hdw_key->master_chain_code[i] = *(seed_digest + 32 + i);
  free(seed_digest);
} 

/* Derive Child keys from HD Wallet master private key and maste chain code
 * hdw: will store new hd wallet structure
 * public_key: 256 bit string
 * chain_code: 256 bit string
 * 32 bit int
*/
void HDW_derive_child_keys(HDWKey *hdw, unsigned char *public_key, unsigned char *chain_code, int index) {
  unsigned char *seed = malloc(68); // public_key (32) + chain_code (32) + index (4) = 68
  // copy public_key, chain_code, index into seed
  int i, j;

  for (i = 0; i < 32; i++) {
    seed[i] = public_key[i];
    seed[i + 32] = chain_code[i];
  }
  // copy int 4 bytes into 
  for (i = 64, j = 3; j >= 0; j--) {
    int offset = 8 * j;
    // mask 8 bits << apply mask to offset of int index, shift bits to low order
    unsigned int mask = ((1 << 8) -1); // create lenght of mask
    unsigned int offset_mask = mask << offset;
    unsigned int applied_mask = index & offset_mask;
    unsigned int lsb = applied_mask >> offset; // least significant bytes
    seed[i++] = lsb; // store lsb  
    printf("%d\n", seed[i-1]);

  }

  for (int i = 64; i < 68; i++) 
      printf("%d\n", seed[i]);
 
 printf("\n"); 

}

