#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"
#include "Device.h"
#include "enolaTrampoline.h"
#include "aes.h"
#include "simple-crypto.h"
#include "hash.h"
#include "rsa.h"

static FILE __stdio = FDEV_SETUP_STREAM(stdout_putchar, NULL, NULL, _FDEV_SETUP_WRITE);
FILE *const stdin = &__stdio;
__strong_reference(stdin, stdout);
__strong_reference(stdin, stderr);

/* Common main.c for the benchmarks

   Copyright (C) 2014 Embecosm Limited and University of Bristol
   Copyright (C) 2018-2019 Embecosm Limited

   Contributor: James Pallister <james.pallister@bristol.ac.uk>
   Contributor: Jeremy Bennett <jeremy.bennett@embecosm.com>

   This file is part of Embench and was formerly part of the Bristol/Embecosm
   Embedded Benchmark Suite.

   SPDX-License-Identifier: GPL-3.0-or-later */


  uint8_t plaintext[] = {0x1a, 0x1b, 0x1c, 0x2d, 0xe, 0xf, 0xa, 0xb};
    //uint8_t ciphertext[1024];
      //uint8_t hash_out[16];
  byte cipher[400]; // 256 bytes is large enough to store 2048 bit RSA ciphertext
  byte n[] = {
    0xEB, 0x6B, 0x1B, 0x08, 0x54, 0x19, 0xA6, 0x4F, 0x11, 0x02, 0x7A, 0xE0, 0x16, 0xA1, 0x54, 0x07,
    0x2C, 0xF8, 0x64, 0x95, 0xA8, 0x7F, 0x1A, 0x31, 0x73, 0xCB, 0xE8, 0x33, 0xA0, 0xF7, 0x81, 0x1F,
    0xAA, 0xD8, 0x31, 0x0F, 0xBB, 0xAD, 0xFD, 0xD6, 0xB2, 0x3A, 0xF5, 0x70, 0xE8, 0xB3, 0x66, 0xC3,
    0x72, 0x31, 0xCE, 0x72, 0x6E, 0x62, 0x5F, 0x1F, 0xC3, 0xB5, 0x6D, 0x34, 0x7A, 0x61, 0x51, 0x88,
    0x35, 0xF2, 0xB2, 0xFC, 0xC2, 0x9C, 0xA2, 0x91, 0xDD, 0x97, 0x13, 0xA8, 0x1F, 0x0F, 0xA5, 0xC2,
    0xB2, 0x82, 0xD9, 0xBB, 0x28, 0x73, 0xF4, 0x06, 0x31, 0x94, 0xE7, 0xFD, 0x90, 0x15, 0x37, 0x74,
    0xDE, 0xC7, 0x42, 0x7C, 0xC4, 0x3F, 0xFE, 0x93, 0x5D, 0x12, 0x86, 0xAA, 0x46, 0x9A, 0xE2, 0x1E,
    0x77, 0x2D, 0x78, 0xB6, 0x76, 0x90, 0x63, 0x97, 0xBD, 0x84, 0x4F, 0xE1, 0xAA, 0x23, 0x44, 0x45,
    0x62, 0x6A, 0x7A, 0x37, 0xAD, 0x20, 0x1B, 0x79, 0x94, 0xC1, 0x72, 0xFA, 0xB6, 0xE2, 0x72, 0xA1,
    0xB1, 0x60, 0xC9, 0x2A, 0x2D, 0xEC, 0xA3, 0x69, 0xD6, 0x18, 0x8A, 0x7A, 0xF1, 0xCF, 0xCA, 0x94,
    0xE4, 0x61, 0x93, 0xF2, 0x33, 0x54, 0x65, 0x99, 0x8A, 0x7F, 0xEC, 0x72, 0x94, 0xC0, 0x78, 0x26,
    0x6B, 0x76, 0x92, 0x02, 0x81, 0xE1, 0x89, 0x8A, 0x52, 0xF2, 0x1E, 0xF9, 0x87, 0xE2, 0x40, 0xDA,
    0x93, 0x2B, 0xB5, 0x12, 0x19, 0xE8, 0x10, 0x2C, 0x21, 0xC3, 0x22, 0x8D, 0xA1, 0xFD, 0x42, 0xF2,
    0xAF, 0x0E, 0x43, 0x23, 0xFE, 0x56, 0xE4, 0xDC, 0x5C, 0x07, 0xD6, 0x92, 0x37, 0x6C, 0xDD, 0xC0,
    0xD4, 0x83, 0xEB, 0x24, 0x06, 0xD7, 0x96, 0x73, 0xF1, 0x2F, 0x1E, 0x02, 0xE8, 0x66, 0x7F, 0xAF,
    0xD5, 0x1F, 0x7B, 0x99, 0xB8, 0x2C, 0xC7, 0x30, 0xAA, 0x6D, 0xC0, 0x1E, 0x3E, 0x7A, 0x8D, 0x13,
  };
  byte e[] = {
      0x01, 0x00, 0x01,
  };
int __attribute__ ((used))
main (int argc __attribute__ ((unused)),
      char *argv[] __attribute__ ((unused)))
{

    /*AES 128-bit test*/
//    Aes ctx;

//    size_t len = 1024;
//     init_trampoline();
//    int result; // Library result
//     if (len <= 0 || len % BLOCK_SIZE)
//         return -1;
//    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
//     if (result != 0)
//         return result; // Report error
//        // Encrypt each block
//     for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
//         result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
//         if (result != 0)
//             return result; // Report error
//     }
//     memset(plaintext, 0, 32*32);
//         // Decrypt each block
//     result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
//     for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
//         result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
//         if (result != 0)
//             return result; // Report error
//     }
  /*MD5sum*/
  //  init_trampoline();
  // size_t len = 1024;

  // wc_Md5Hash(plaintext, len, hash_out);
  /*RSA */
  init_trampoline();
  RsaKey pub;
  int ret;
  ret = wc_InitRsaKey(&pub, NULL);  // not using heap hint. No custom memory
  if ( ret != 0 ) {

  }

  // not using heap hint. No custom memory

  // ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), &pub);
  // if( ret != 0 ) {
  //   // error parsing public key elements
  // }
  ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), &pub);
  if (ret != 0) {
      /* Handle error */
  }

  // ret = wc_RsaPrivateKeyDecode(priv_key, &idx, &pub, sizeof(priv_key));
  // if( ret != 0 ) {
  //     // error parsing private key
  // }
  // idx = 0;
  // ret = wc_RsaPublicKeyDecode(pub_key, &idx, &pub, sizeof(pub_key));
  // if( ret != 0 ) {
  //     // error parsing public key
  // }
  // initialize with received public key parameters
  ret = wc_RsaPublicEncrypt(plaintext, sizeof(plaintext), cipher, sizeof(cipher), &pub, NULL);
  if ( ret < 0 ) {
    /*Error signing*/
  }

}                               /* main () */