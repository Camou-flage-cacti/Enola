#include <stdio.h>
#include "Driver_USART.h"
#include "stdout.h"
#include "Device.h"
#include "enolaTrampoline.h"
#include "support.h"

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




int __attribute__ ((used))
main (int argc __attribute__ ((unused)),
      char *argv[] __attribute__ ((unused)))
{
	int i;
	volatile int result;
	int correct;
	#ifdef ENOLA_DEBUG
	stdout_init();
	#endif

	#ifdef ENOLA_TRACE_DISPLAY
	init_trampoline();
	#endif
	//elapsed_time_init();
	//elapsed_time_start(0);
	result = benchmark ();
	//elapsed_time_stop(0);
	#ifdef ENOLA_DEBUG
	display_elapsed_times();
	#endif

	//correct = verify_benchmark (result);

	#ifdef ENOLA_TRACE_DISPLAY
	print_occurence_trace();
	#endif
	return (!correct);

}                               /* main () */


/*
   Local Variables:
   mode: C
   c-file-style: "gnu"
   End:
*/