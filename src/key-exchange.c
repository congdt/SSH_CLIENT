#include "key-exchange.h"
#include "sshbuf.h"
#include "ssh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int myErrorCode;

int put_keyinit_to_sshbuf(SSH_BUF *sshbuf, KEY_EXCHANGE_INIT key_ex)
{

	if(sshbuf == NULL){
		sshbuf = create_sshbuf();
	}
	else{
		reset_sshbuf(sshbuf);
	}
	int i;	
	
	
	if(!key_ex.key_algo || !key_ex.s_key_algo || !key_ex.enc_algo_ctos
		|| !key_ex.enc_algo_stoc || !key_ex.mac_algo_ctos || !key_ex.mac_algo_stoc
		|| !key_ex.com_algo_ctos || !key_ex.com_algo_stoc || !key_ex.lan_ctos || !key_ex.lan_stoc){
		myErrorCode = ERROR_PUT_KEYINIT;
		return 1;	
	}
	/* compute payload length */
	int payload_length = 1 + 16 + 4 + strlen((char*)key_ex.key_algo) + strlen((char*)key_ex.s_key_algo)
					+ 4 + strlen((char*)key_ex.enc_algo_ctos) + 4 + strlen((char*)key_ex.enc_algo_stoc)
					+ 4 + strlen((char*)key_ex.mac_algo_ctos) + 4 + strlen((char*)key_ex.mac_algo_stoc)
					+ 4 + strlen((char*)key_ex.com_algo_ctos) + 4 + strlen((char*)key_ex.com_algo_stoc)
					+ 4 + strlen((char*)key_ex.lan_ctos) + 4 + strlen((char*)key_ex.lan_stoc)
					+ 1 + 4;
	
	/* compute packet_length, padding_length */
	unsigned int packet_length;
	unsigned char padding_length;
	
	padding_length = 8 -((payload_length + sizeof(packet_length) + sizeof(padding_length)) % 8);
	packet_length = padding_length + payload_length + 1;
	
	
	/* ----------- put all packet into sshbuf ---------------- */
	
	// -- put packet_length & padding_length
	put_uint32_to_sshbuf(sshbuf, packet_length);
	put_byte_to_sshbuf(sshbuf, padding_length);
	
	// -- put payload 
	put_byte_to_sshbuf(sshbuf, key_ex.msgtype);
	for(i = 0; i < 16; i++){
		put_byte_to_sshbuf(sshbuf, key_ex.cookie[i]);
	}
	put_string_to_sshbuf(sshbuf, key_ex.key_algo);
	put_string_to_sshbuf(sshbuf, key_ex.s_key_algo);
	put_string_to_sshbuf(sshbuf, key_ex.enc_algo_ctos);
	put_string_to_sshbuf(sshbuf, key_ex.enc_algo_stoc);
	put_string_to_sshbuf(sshbuf, key_ex.mac_algo_ctos);
	put_string_to_sshbuf(sshbuf, key_ex.mac_algo_stoc);
	put_string_to_sshbuf(sshbuf, key_ex.com_algo_ctos);
	put_string_to_sshbuf(sshbuf, key_ex.com_algo_stoc);
	put_string_to_sshbuf(sshbuf, key_ex.lan_ctos);
	put_string_to_sshbuf(sshbuf, key_ex.lan_stoc);
	put_uint32_to_sshbuf(sshbuf, key_ex.use_in_future);
	
	// put random padding
	for(i = 0; i < padding_length; i++){
		put_byte_to_sshbuf(sshbuf, (unsigned char)i);
	}
	
	return 0;
}

int get_keyinit_from_sshbuf(SSH_BUF *sshbuf, KEY_EXCHANGE_INIT *key_ex)
{
	int i;
	unsigned int packet_length;
	unsigned char padding_length;
	if(sshbuf == NULL){
		myErrorCode = ERROR_GET_KEYINIT;
		return 1;
	}
	get_uint32_from_sshbuf(sshbuf, &packet_length);
	get_byte_from_sshbuf(sshbuf, &padding_length);
	
	// get payload
	get_byte_from_sshbuf(sshbuf, &key_ex->msgtype);
	for(i = 0; i < 16; i++){
		get_byte_from_sshbuf(sshbuf, (unsigned char*)&key_ex->cookie[i]);
	}
	get_string_from_sshbuf(sshbuf, key_ex->key_algo, 500);
	get_string_from_sshbuf(sshbuf, key_ex->s_key_algo, 500);
	get_string_from_sshbuf(sshbuf, key_ex->enc_algo_ctos,500);
	get_string_from_sshbuf(sshbuf, key_ex->enc_algo_stoc,500);
	get_string_from_sshbuf(sshbuf, key_ex->mac_algo_ctos,500);
	get_string_from_sshbuf(sshbuf, key_ex->mac_algo_stoc,500);
	get_string_from_sshbuf(sshbuf, key_ex->com_algo_ctos,500);
	get_string_from_sshbuf(sshbuf, key_ex->com_algo_stoc,500);
	get_string_from_sshbuf(sshbuf, key_ex->lan_ctos,500);
	get_string_from_sshbuf(sshbuf, key_ex->lan_stoc,500);
	get_byte_from_sshbuf(sshbuf, &(key_ex->first_key));
	get_uint32_from_sshbuf(sshbuf, &(key_ex->use_in_future));
	
	/* get random padding
	for(i = 0; i < padding_length; i++){
		get_byte_to_sshbuf(sshbuf, i);
	}
	*/
		
	printf("1.%s\n2.%s\n3.%s\n4.%s\n5.%s\n6.%s\n7.%s\n8.%s\n9.%s\n10.%s", key_ex->key_algo, key_ex->s_key_algo, key_ex->enc_algo_ctos, key_ex->enc_algo_stoc, key_ex->mac_algo_ctos, key_ex->mac_algo_stoc, key_ex->com_algo_ctos, key_ex->com_algo_stoc, key_ex->lan_ctos, key_ex->lan_stoc);
	return 0;
}
