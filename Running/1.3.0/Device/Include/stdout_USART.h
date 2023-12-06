/*
 * Copyright (c) 2023 Arm Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __STDOUT_USART_H__
#define __STDOUT_USART_H__

#include "Driver_USART.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  Initialize stdout

  \return          0 on success, or -1 on error.
*/
int stdout_init (void);

/* Redirects printf to STDIO_DRIVER in case of ARMCLANG*/
#if defined(__ARMCC_VERSION)
/* Struct FILE is implemented in stdio.h. Used to redirect printf to
 * STDIO_DRIVER
 *
 * FILE __stdout;
 * __ARMCC_VERSION is only defined starting from Arm compiler version 6 */
int stdout_putchar(const unsigned char ch);
#elif defined(__GNUC__)
/* Redirects printf to STDIO_DRIVER in case of GNUARM */
int _write(int fd, char *str, int len);
#elif defined(__ICCARM__)
/**
  Put a character to the stdout

  \param[in]   ch  Character to output
  \return          The character written, or -1 on write error.
*/
int fputc(int ch);
size_t __write(int handle, const unsigned char * buffer, size_t size);
#endif

#ifdef __cplusplus
}
#endif
#endif /* __STDOUT_USART_H__ */
