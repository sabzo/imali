/* Examples */
#include "../lib/lib.h"

int main() {
  EC_KEY *ec_key = NULL;
  EC_KEY *eck2 = NULL;
  const BIGNUM *prv = NULL;
  const EC_POINT *pub = NULL;
  unsigned char msg[33] = {0};
  unsigned char prv_str[33] = {0};
  unsigned int digest_len = 0;

  random_256bit_string(msg);
  printf("random 256bit string:");
  for (int i = 0; i < 32; i++)
       printf("%02x", msg[i]);

  ec_key = init_priv_pub_key_pair();
  const unsigned char *addr = NULL; 

  if ((prv = get_private_key(ec_key)) == NULL) {
    printf("Unable to get private key\n");
    exit(-1);
  }

  BN_bn2bin(prv, prv_str);
  printf("\nprivate key 1 %s\npublic key 1: %s\n", BN_bn2hex(prv), pub_key_hex(ec_key));
  
  /* Generate Public Key from private key */
  eck2 = gen_pub_key_from_priv_key(msg);

  if ((prv = get_private_key(eck2)) == NULL) {
    printf("Unable to get private key 2\n");
    exit(-1);
  }

  if ((pub = get_public_key(eck2)) == NULL) {
    printf("Unable to get public key 2\n");
    exit(-1);
  }

  //  printf("\nprivate key 2 %s\n public key2: %s\n\n", BN_bn2hex(prv), pub_key_hex(eck2));

  // get address
  addr = mget_address(ec_key, &digest_len);

  printf("Address: \n");
  for (int i = 0; i < digest_len; i++)
       printf("%02x", addr[i]);
  printf("\nDigest Length: %d\n", digest_len);
  
  unsigned char *checksum = NULL;
  // Base58Check encode
  for (int i = 0; i < 2; i++) {
    checksum = mbase58EncodeChecksum(0, addr, digest_len, 4);
    printf("checksum 1: ");
    for (int i = 0; i < 4; i++)
         printf("%02x", checksum[i]);
    printf("\nchecksum 2: ");
    checksum = mbase58EncodeChecksum(0, addr, digest_len, 4);
    for (int i = 0; i < 4; i++)
         printf("%02x", checksum[i]);
    printf("\n");
  }

  int b58l = 0;
  const unsigned char *hash = mb58Encode(addr, digest_len, &b58l);
  printf("addr b58: %s\n", hash + b58l);
  free(hash);
  return 0;
}
