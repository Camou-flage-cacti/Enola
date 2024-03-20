#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"
#include "enolaTrampoline.h"
#include "blake2-kat.h"
#include "blake2.h"
static FILE __stdio = FDEV_SETUP_STREAM(stdout_putchar, NULL, NULL, _FDEV_SETUP_WRITE);
FILE *const stdin = &__stdio;
__strong_reference(stdin, stdout);
__strong_reference(stdin, stderr);


/*int main(void)
{
	stdout_init();
	printf("\r\n= Hello World LLVM5=\r\n");
}*/


int main(void)
{
	stdout_init();
	elapsed_time_init();
	/*Blake2s*/
	uint8_t key[BLAKE2S_KEYBYTES];
	uint8_t buf[BLAKE2_KAT_LENGTH];
	size_t i, step;

	for( i = 0; i < BLAKE2S_KEYBYTES; ++i )
		key[i] = ( uint8_t )i;

	for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
		buf[i] = ( uint8_t )i;

	/* Test simple API */
	for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
	{
		uint8_t hash[BLAKE2S_OUTBYTES];
		elapsed_time_start(0);
		blake2s( hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES );
		elapsed_time_stop(0);
  	}


	/*blake2sp*/
	// uint8_t key[BLAKE2S_KEYBYTES];
	// uint8_t buf[BLAKE2_KAT_LENGTH];
	// size_t i, step;

	// for( i = 0; i < BLAKE2S_KEYBYTES; ++i )
	// 	key[i] = ( uint8_t )i;

	// for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
	// 	buf[i] = ( uint8_t )i;

	// /* Test simple API */
	// for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
	// {
	// 	uint8_t hash[BLAKE2S_OUTBYTES];
	// 	blake2sp( hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES );
	// }


	/*blake2b*/
	// uint8_t key[BLAKE2B_KEYBYTES];
	// uint8_t buf[BLAKE2_KAT_LENGTH];
	// size_t i, step;

	// for( i = 0; i < BLAKE2B_KEYBYTES; ++i )
	// 	key[i] = ( uint8_t )i;

	// for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
	// 	buf[i] = ( uint8_t )i;

	// /* Test simple API */
	// for( i = 0; i < 1; ++i )
	// {
	// 	uint8_t hash[BLAKE2B_OUTBYTES];
	// 	elapsed_time_start(0);
	// 	blake2b( hash, BLAKE2B_OUTBYTES, buf, i, key, BLAKE2B_KEYBYTES );
	// 	elapsed_time_stop(0);
	// }
	display_elapsed_times();
	return 0;
}
