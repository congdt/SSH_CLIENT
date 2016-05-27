#include <stdio.h>
#include "sshbuf.h"
#include "ssh.h"
#include <string.h>
#include <stdlib.h>

int myErrorCode = 0;

SSH_BUF *create_sshbuf()
{
	SSH_BUF *temp = (SSH_BUF*)malloc(sizeof(SSH_BUF));
	temp->offset = 0;
	temp->length = 0;
	return temp;
}

void reset_sshbuf(SSH_BUF *sshbuf)
{
	sshbuf->offset = 0;
	sshbuf->length = 0;
}

void free_sshbuf(SSH_BUF *sshbuf){
	free(sshbuf);
}



int put_byte_to_sshbuf(SSH_BUF *sshbuf, unsigned char a)
{
	if(sshbuf == NULL || sshbuf->length + 1 > MAX_LENGTH){
		myErrorCode = ERROR_PUT_BYTE_TO_SSHBUF;
		return 1;
		
	}
	sshbuf->buf[sshbuf->length] = a;
	sshbuf->length += 1;
	return 0;
}


// need size of sshbuf to prevent from buffer overflow
int put_uint32_to_sshbuf(SSH_BUF *sshbuf, unsigned int a)
{
	if(sshbuf == NULL || (sshbuf->length + 4 > MAX_LENGTH)){
		myErrorCode = ERROR_PUT_UINT32_TO_SSHBUF;
		return 1;
	}
	int i;
	for(i = 0; i < 4; i++){
		sshbuf->buf[sshbuf->length + i] = (a >> (32-8*i-8)) & 0xff;
	}
	sshbuf->length += 4;
	return 0;
}

int put_uint64_to_sshbuf(SSH_BUF *sshbuf, unsigned long a)
{
	if(sshbuf == NULL || (sshbuf->length+8 > MAX_LENGTH)){
		myErrorCode = ERROR_PUT_UINT64_TO_SSHBUF;
		return 1;
	}
	int i;
	for(i = 0; i < 8; i++){
		sshbuf->buf[sshbuf->length + i] = (a >> (64-8*i-8)) & 0xff;
	}
	sshbuf->length += 8;
	return 0;
}

int put_string_to_sshbuf(SSH_BUF *sshbuf, unsigned char *s)
{
	if(sshbuf == NULL || s == NULL || (sshbuf->length)+strlen((char*)s) > MAX_LENGTH){
		myErrorCode = ERROR_PUT_STRING_TO_SSHBUF;
		return 1;
	}
	unsigned int len = strlen((char*)s);
	put_uint32_to_sshbuf(sshbuf, len); 		
	int i;
	for(i = 0 ; i < len; i++){
		sshbuf->buf[sshbuf->length + i] = s[i];
	}
	sshbuf->length += len;
	return 0;
}

/*
int put_bignum_to_sshbuf(SSH_BUF *sshbuf, BIGNUM *d)
{
	
	return 0;
}
*/

int get_byte_from_sshbuf(SSH_BUF *sshbuf, unsigned char *a)
{
	if(sshbuf == NULL || a == NULL || (sshbuf->offset + 1 > sshbuf->length)){
		myErrorCode = ERROR_GET_BYTE_FROM_SSHBUF;
		return 1;
	}
	*a = sshbuf->buf[sshbuf->offset];
	sshbuf->offset++;
	return 0;
}

int get_uint32_from_sshbuf(SSH_BUF *sshbuf, unsigned int *a ){
	if(sshbuf == NULL || a == NULL || (sshbuf->offset + 4 > sshbuf->length)){
		myErrorCode = ERROR_GET_UINT32_FROM_SSHBUF;
		return 1;
	}
	*a = 0x00000000;
	int i;
	for(i = 0; i < 4; i++){
		
		*a |= sshbuf->buf[sshbuf->offset + i] << (32 - 8 - 8*i) ;
	}
	sshbuf->offset += 4;
	return 0;
}

int get_uint64_from_sshbuf(SSH_BUF *sshbuf, unsigned long *a)
{
	if(sshbuf == NULL || a == NULL || (sshbuf->offset + 8 > sshbuf->length)){
		myErrorCode = ERROR_GET_UINT64_FROM_SSHBUF;
		return 1;
	}
	*a = 0x0000000000000000;
	int i;
	for(i = 0; i < 8; i++){
		
		*a |= sshbuf->buf[sshbuf->offset + i] << (64 - 8 - 8*i) ;
	}
	sshbuf->offset += 8;
	return 0;
}

/*
	RECOMMEND use Dynamic memory
	
	+ free(s) => malloc/calloc
	+ realloc(s);
	
*/
int get_string_from_sshbuf(SSH_BUF *sshbuf, unsigned char *s, unsigned int size)
{
	if(sshbuf==NULL || (sshbuf->offset + 4 > sshbuf->length)){
		myErrorCode = ERROR_GET_STRING_FROM_SSHBUF_1;
		return 1;
	}
	unsigned int len;
	get_uint32_from_sshbuf(sshbuf, &len);
	
	if(len >= size || sshbuf->length - sshbuf->offset - len< 0){ //overflow sshbuf->buf
		myErrorCode = ERROR_GET_STRING_FROM_SSHBUF_2;
		return 1;
	}
	if(s == NULL){
		s = (unsigned char*)malloc(len + 1);
		if(s == NULL){
			myErrorCode = ERROR_GET_STRING_FROM_SSHBUF_1;
			return 1;
		}
	}
	else{
		free(s);
		s = (unsigned char*)malloc(len + 1);
		if(s == NULL){
			myErrorCode = ERROR_GET_STRING_FROM_SSHBUF_2;
			return 1;
		}
	}
	int i;
	for(i = 0; i < len; i++){
		s[i] = sshbuf->buf[sshbuf->offset + i];
	}
	s[i] = '\0';
	sshbuf->offset += len;
	return 0;
}

/*
int get_bignum_from_sshbuf(SSH_BUF *sshbuf, BIGNUM *d)
{
	
}
*/
