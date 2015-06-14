#include "ipsum.h"

/************************************************************
 Checksum for Internet Protocol family headers (C Version)
 From ping examples in W.Richard Stevens "UNIX NETWORK PROGRAMMING" book.
 ************************************************************/
#include <inttypes.h>

int ip_sum(char* packet, int n) {
	uint16_t *p = (uint16_t*)packet;
	uint16_t answer;
	long sum = 0;
	uint16_t odd_byte = 0;
	uint8_t count = 0;

	while (n > 1) {
		if (count != 5) {
			sum += *p++;
			n -= 2;
		}
		else {
			p++;
			n -= 2;
		}
		count++;
	}

	/* mop up an odd byte, if necessary */
	if (n == 1) {
		*(uint8_t*)(&odd_byte) = *(uint8_t*)p;
		sum += odd_byte;
	}

	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);           /* add carry */
	answer = ~sum;                /* ones-complement, truncate*/
	return answer;
}
