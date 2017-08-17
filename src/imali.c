/* Examples */
#include "../lib/lib.h"

int main() {
  EC_KEY *ec_key = NULL;
  EC_KEY *eck2 = NULL;
  const BIGNUM *prv = NULL;
  const EC_POINT *pub = NULL;
  unsigned char msg[33] = {0};
  unsigned char prv_str[33] = {0};
  unsigned char pub_str[33] = {0};
  unsigned int digest_len = 0;

  // Test Random Bit String
  random_256bit_string(msg);
  printf("Getting random 256bit string:");
  for (int i = 0; i < 32; i++)
       printf("%02x", msg[i]);
  printf("\n\n");


  // Generat a private and public key pair
  printf("Generating a private and public key pair using init_priv_pub_key_pair()...\n");
  ec_key = init_priv_pub_key_pair();
  const unsigned char *addr = NULL; 

  if ((prv = get_private_key(ec_key)) == NULL) {
    printf("Unable to get private key\n");
    exit(-1);
  }

  BN_bn2bin(prv, prv_str);
  printf("private key 1 %s\npublic key 1: %s\n", BN_bn2hex(prv), pub_key_hex(ec_key));
  
  printf("\n Generating a public key from randomly chose 256-bit string...\n");
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

  printf("private key 2 %s\n public key2: %s\n\n", BN_bn2hex(prv), pub_key_hex(eck2));

  /* Get Address of Wallet */
  // get address
  printf("Generating wallet address using supplied public key...\n");
  addr = mget_address(ec_key, &digest_len);

  printf("Address: \n");
  for (int i = 0; i < digest_len; i++) {
       printf("%02x", addr[i]);
  }
  printf("\nAddress Length is: %d\n", digest_len);
 
  // print checksum of address
  printf("Printing base58 checksum of address. This will loop several times to see if output repeats as it should\n");
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

  printf("\n");
  int offset = 0;

  // Base 58 Encoding
  printf("base58Encoding test ... \n");
  unsigned char h[] = "hello";
  unsigned char *hash = mb58Encode(h, 5, &offset);//addr, digest_len, &b58l);
  printf("hello in b58: %s\n", hash + offset);

  hash = mb58Encode(addr, digest_len, &offset);
  printf("addr in b58: %s\n", hash + offset);

  // Decoding
  printf("Test decoding Base58...\n"); 
  int ret_len = 0;
  unsigned char *hp = mbase58Decode(hash + offset, BASE58_LEN - 1 - offset, &ret_len); // - 1 because string is null terminated  
  printf("Size of Address mbase58 Decoded string is: %d\n", ret_len);

  // Decoded Address
  printf("Decoded Addres:\n");
  for (int i = 0; i < ret_len; i++) {
         printf("%02x", hp[i]);
   }
  printf("\n");
  
  free(hp);
  free(hash);
  
  /* Test HDW */
  printf("Generate seed for HDwallet: \n");
  unsigned char *seed = mHDW_seed_key_create();
  for (int i = 0; i < 32; i++)
      printf("%x", seed[i]);
  printf("\n");
 
  /* Get mnemonic words array */
  char **words = mWords_from_file(NULL);  
  int i = 0;
  while (i < 2048)
      free(words[i++]);
  free(words);

  char **phrase = mHDW_key_mnemonic();
  for(int i = 0; i < 24; i++) 
      printf("%s ", phrase[i]);

  // HD Wallet init
  HDWKey hdw_key = {};
  HDW_init(&hdw_key);
  

  printf("Master Chain Code: \n");
  for (int i = 0; i < 256; i++)
      printf("%x", hdw_key.master_chain_code[i]);
  printf("\n");
  
  prv = get_private_key(eck2);

  BN_bn2bin(prv, prv_str);
  HDWKey hdw = {};

  printf("Getting Child Key\n");

  HDW_derive_child_keys(&hdw, pub_str, msg, 455);
  printf("Child Key Chain Code: \n");
  for (int i = 0; i < 256; i++)
      printf("%x", hdw_key.master_chain_code[i]);
  printf("\n");

  char four[] = {1, 2, 3, 4, 5};
  char five[] = {6, 7, 8, 9, 10};
  char result[5] = {0};

  int carry = mprecision_add(four, five, result, 5);
  printf("carry: %d\n", carry);
  for (int i = 0; i < 5; i++)
    printf("%d ", result[i]);
  printf("\n");


  free(ec_key);
  free(eck2);

  return 0;
}
