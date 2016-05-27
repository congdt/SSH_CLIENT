#ifndef _KEY_EXCHANGE_H_
#define _KEY_EXCHANGE_H_

typedef struct{
	char msgtype;
	char cookie[16];
	char *key_algo;
	char *s_key_algo;		// server host key algo, or client lists the argo that willing to accept
	char *enc_algo_ctos;
	char *enc_algo_stoc;
	char *mac_algo_ctos;
	char *mac_algo_stoc;
	char *com_algo_ctos;
	char *com_algo_stoc;
	char *lan_ctos;
	char *lan_stoc;
	bool first_key;
	int use_in_future;
} KEY_EX;


#endif
