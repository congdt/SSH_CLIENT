#include <stdio.h>
#include "sshbuf.h"
#include "ssh.h"
#include <stdlib.h>

int main(int argc, char ** argv)
{
	SSH_BUF *sshbuf = (SSH_BUF *) malloc(sizeof(SSH_BUF));
	sshbuf->length = 0;
	sshbuf->offset = 0;
	int i;
	char *s1 = "hahaha";
	char s2[7]={0, 0, 0, 0 , 0, 0, 0};
	unsigned int a = 100;
	unsigned long b = 200;
	unsigned char c = 28;
	
	put_uint32_to_sshbuf(sshbuf, a);
	for(i = 0; i <= sshbuf->length; i++){
		printf("%02x", sshbuf->buf[i]);
	}
	printf("\n");
	put_uint64_to_sshbuf(sshbuf, b);
	for(i = 0; i <= sshbuf->length; i++){
		printf("%02x", sshbuf->buf[i]);
	}
	printf("\n");
	put_byte_to_sshbuf(sshbuf, c);
	for(i = 0; i <= sshbuf->length; i++){
		printf("%02x", sshbuf->buf[i]);
	}
	printf("\n");
	put_string_to_sshbuf(sshbuf, s1);
	for(i = 0; i <= sshbuf->length; i++){
		printf("%02x", sshbuf->buf[i]);
	}
	
	// get info
	get_uint32_from_sshbuf(sshbuf, &a);
	get_uint64_from_sshbuf(sshbuf, &b);
	get_byte_from_sshbuf(sshbuf, &c);
	get_string_from_sshbuf(sshbuf, s2, 7);
	
	printf("\na = %d \nb=%d \nc=%d", a, b, c);
	printf("\n %s", s2);
	free(sshbuf);
	return 0;
}
