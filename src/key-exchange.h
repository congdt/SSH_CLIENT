#ifndef _KEY_EXCHANGE_H_
#define _KEY_EXCHANGE_H_

#include "sshbuf.h"

typedef struct{
	unsigned char msgtype;
	unsigned char cookie[16];
	unsigned char *key_algo;
	unsigned char *s_key_algo;		// server host key algo, or client lists the argo that willing to accept
	unsigned char *enc_algo_ctos;
	unsigned char *enc_algo_stoc;
	unsigned char *mac_algo_ctos;
	unsigned char *mac_algo_stoc;
	unsigned char *com_algo_ctos;
	unsigned char *com_algo_stoc;
	unsigned char *lan_ctos;
	unsigned char *lan_stoc;
	unsigned char first_key;
	unsigned int use_in_future;
} KEY_EXCHANGE_INIT;


int put_keyinit_to_sshbuf(SSH_BUF *sshbuf, KEY_EXCHANGE_INIT key_ex);
int get_keyinit_to_sshbuf(SSH_BUF *sshbuf, KEY_EXCHANGE_INIT *key_ex);


#endif
