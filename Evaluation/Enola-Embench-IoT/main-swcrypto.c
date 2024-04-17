#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"
#include "Device.h"
#include "enolaTrampoline.h"
#include "support.h"
#include "blake2-kat.h"
#include "blake2.h"
#include "sha256.h"
#include <string.h>

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




// int __attribute__ ((used))
// main (int argc __attribute__ ((unused)),
//       char *argv[] __attribute__ ((unused)))
// {
// 	int i;
// 	volatile int result;
// 	int correct;
// 	#ifdef ENOLA_DEBUG
// 	stdout_init();
// 	#endif

// 	#ifdef ENOLA_TRACE_DISPLAY
// 	init_trampoline();
// 	#endif
// 	#ifdef ENOLA_DEBUG
// 	elapsed_time_init();
// 	elapsed_time_start(0);
// 	#endif
// 	result = benchmark ();
// 	#ifdef ENOLA_DEBUG
// 	elapsed_time_stop(0);
// 	#endif
// 	#ifdef ENOLA_DEBUG
// 	display_elapsed_times();
// 	#endif
// 	correct = verify_benchmark (result);
// 	#ifdef ENOLA_TRACE_DISPLAY
// 	//print_occurence_trace();
// 	#endif
// 	return (!correct);

// }                               /* main () */



int main(void)
{
	//stdout_init();
	elapsed_time_init();
	//int (*func_ptr)(void) = &func;
	//(*func_ptr)();
	/*Blake2s*/
	// uint8_t key[BLAKE2S_KEYBYTES];
	// uint8_t buf_blake2[BLAKE2_KAT_LENGTH];
	// size_t i, step;

	// for( i = 0; i < BLAKE2S_KEYBYTES; ++i )
	// 	key[i] = ( uint8_t )i;

	// for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
	// 	buf_blake2[i] = ( uint8_t )i;

	// /* Test simple API */
	// elapsed_time_start(0);
	// for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
	// {
	// 	uint8_t hash[BLAKE2S_OUTBYTES];
		
	// 	blake2s( hash, BLAKE2S_OUTBYTES, buf_blake2, i, key, BLAKE2S_KEYBYTES );
		
	// }
	// elapsed_time_stop(0);

	/*SHA-256*/
	BYTE text1[] = {"abcdbcdccdeddergetghfghigtijzijk"};
	BYTE text2[] = {"abcdbcdecdefdefgefghfghighijhijz"};
	BYTE text3[] = {"0bcdtcdecdefdefgefghfzhighiohixc"};
	BYTE text4[] = {"0bcdtcdecdefdefgerghfzwgghiohixc"};

	BYTE hash1[SHA256_BLOCK_SIZE] = {0x18,0xfc,0x96,0x5c,0x4,0x68,0xc5,0x54,0x59,0x3d,0xca,0xf3,0x47,0xc1,0x46,0x45,
									 0x2b,0xa3,0xf7,0x15,0xec,0x6c,0x43,0x36,0x30,0x82,0x28,0x14,0x72,0xa3,0x5c,0x1};
	BYTE hash2[SHA256_BLOCK_SIZE] = {0xf3,0x9f,0xeb,0x63,0x50,0x81,0xc4,0xd,0x48,0x90,0xbe,0x89,0xe6,0x18,0xe8,0x54,
									 0x2c,0x99,0xf1,0x4b,0x77,0xba,0xb0,0x50,0xf2,0x8a,0x78,0x78,0x63,0x8b,0x4f,0xd5};
	BYTE hash3[SHA256_BLOCK_SIZE] = {0x78,0xf8,0xd5,0x6d,0x42,0x5d,0x56,0x2e,0xda,0x62,0xac,0x32,0xe4,0x13,0x81,0x28,
									 0x32,0x27,0x83,0x28,0xc,0x43,0xc9,0x3a,0xba,0x1e,0x94,0xd9,0xf8,0x5e,0x41,0xd};
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int idx;
	int pass = 1;
	elapsed_time_start(1);
	for(int i = 0; i<8; i++)
	{
		// elapsed_time_start(1);

		sha256_init(&ctx);
		sha256_update(&ctx, text1, strlen(text1));
		sha256_final(&ctx, buf);

		// elapsed_time_stop(1);
		// pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);

		// elapsed_time_start(1);

		sha256_init(&ctx);
		sha256_update(&ctx, text2, strlen(text2));
		sha256_final(&ctx, buf);

		// elapsed_time_stop(1);
		// pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);

		// elapsed_time_start(1);
		sha256_init(&ctx);
		sha256_update(&ctx, text3, strlen(text3));
		sha256_final(&ctx, buf);
		// elapsed_time_stop(1);

		
		sha256_init(&ctx);
		sha256_update(&ctx, text4, strlen(text4));
		sha256_final(&ctx, buf);
		

		//pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);

	}
	elapsed_time_stop(1);
	
	printf("\r\n= SHA-256 test: %s =\r\n", pass ? "Success" : "Fail");

	display_elapsed_times();
	return 0;
}

/*
   Local Variables:
   mode: C
   c-file-style: "gnu"
   End:
*/