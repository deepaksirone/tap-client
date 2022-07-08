#ifndef _KEYSTORE_REPORT_H_
#define _KEYSTORE_REPORT_H_

#define MDSIZE 64
#define ATTEST_DATA_MAXLEN 1024
#define PUBLIC_KEY_SIZE 32
#define SIGNATURE_SIZE 64

#include <stdint.h>

typedef unsigned char byte;

struct enclave_report_t {
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};

struct sm_report_t {
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

struct report_t {
  struct enclave_report_t enclave;
  struct sm_report_t sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

#endif
