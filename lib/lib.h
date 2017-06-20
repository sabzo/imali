#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define MESSAGE ((const unsigned char *) "test")
#define MESSAGE_LEN 4

void get_sha_256(unsigned char out[crypto_hash_sha256_BYTES]) {
  unsigned char message[32]; // 32 bytes
  int fd;
  int n_read;

  fd = open("/dev/urandom", O_RDONLY, 0);
  // TODO: ensure message < (1.158 * 10^77) -1, which is slightly less than 2^256
  if ((n_read = read(fd, message, 32)) == -1) { 
    printf("Error getting random values\n");
    exit(1);
  }

  crypto_hash_sha256(out, MESSAGE, MESSAGE_LEN);
  close(fd);
}
