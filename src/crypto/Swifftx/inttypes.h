 /*
  inttypes.h

  Contributors:
    Created by Marek Michalkiewicz <marekm@linux.org.pl>

  THIS SOFTWARE IS NOT COPYRIGHTED

  This source code is offered for use in the public domain.  You may
 use, modify or distribute it freely.

 This code is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY.  ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 DISCLAIMED.  This includes but is not limited to warranties of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/
 
 #ifndef __INTTYPES_H_
#define __INTTYPES_H_

/* Check if int8_t, int16_t, etc., are already defined */
#ifndef int8_t
typedef signed char int8_t;
#endif

#ifndef uint8_t
typedef unsigned char uint8_t;
#endif

#ifndef int16_t
typedef short int int16_t;
#endif

#ifndef uint16_t
typedef unsigned short int uint16_t;
#endif

#ifndef int32_t
typedef int int32_t;
#endif

#ifndef uint32_t
typedef unsigned int uint32_t;
#endif

#ifndef int64_t
typedef long long int int64_t;
#endif

#ifndef uint64_t
typedef unsigned long long int uint64_t;
#endif

/* Handle platform-specific intptr_t and uintptr_t */
#ifdef __APPLE__  // macOS or iOS platform
#include <sys/types.h>  // Includes __darwin_intptr_t and uintptr_t definitions

#ifndef intptr_t
typedef __darwin_intptr_t intptr_t;  // Defined as 'long' on macOS
#endif

#ifndef uintptr_t
typedef unsigned long uintptr_t;  // Defined as 'unsigned long' on macOS
#endif

#else  // Other platforms (Linux, Windows, etc.)

#ifndef intptr_t
typedef int16_t intptr_t;  // Defined as 'short int' on other platforms
#endif

#ifndef uintptr_t
typedef uint16_t uintptr_t;  // Defined as 'unsigned short' on other platforms
#endif

#endif /* __APPLE__ */

#endif /* __INTTYPES_H_ */
