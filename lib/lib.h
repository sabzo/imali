#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define MESSAGE_LEN 32

void get_sha_256(unsigned char out[crypto_hash_sha256_BYTES]) {
  unsigned char msg[32]; // 32 bytes
  int fd;
  int n_read;

  fd = open("/dev/urandom", O_RDONLY, 0);
  // TODO: To match Bitcoin elliptic curve key gen ensure msg bits are < (1.158 * 10^77) -1, which is slightly less than 2^256

  if ((n_read = read(fd, msg, MESSAGE_LEN)) == -1) { 
    printf("Error getting random values\n");
    exit(1);
  }

  crypto_hash_sha256(out, msg, MESSAGE_LEN);
  close(fd);
}
