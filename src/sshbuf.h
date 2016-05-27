#ifndef SSHBUF_H_
#define SSHBUF_H_

#define MAX_LENGTH 32768


typedef struct {
	int length;
	int offset;
	unsigned char buf[MAX_LENGTH];
} SSH_BUF;

SSH_BUF* create_sshbuf();
void free_sshbuf(SSH_BUF *sshbuf);
void reset_sshbuf(SSH_BUF *sshbuf);

int put_byte_to_sshbuf(SSH_BUF *sshbuf, unsigned char a);
int put_uint32_to_sshbuf(SSH_BUF *sshbuf, unsigned int a);
int put_uint64_to_sshbuf(SSH_BUF *sshbuf, unsigned long a);
int put_string_to_sshbuf(SSH_BUF *sshbuff, unsigned char *s);


//int put_bignum_to_sshbuf(unsigned char *sshbuf, BIGNUM *d);

int get_byte_from_sshbuf(SSH_BUF *sshbuf, unsigned char *a);
int get_uint32_from_sshbuf(SSH_BUF *sshbuf, unsigned int *a);
int get_uint64_from_sshbuf(SSH_BUF *sshbuf, unsigned long *a);
int get_string_from_sshbuf(SSH_BUF *sshbuf, unsigned char *s, unsigned int size);

//int get_bignum_from_sshbuf(unsigned char *sshbuf, BIGNUM *d);
#endif
