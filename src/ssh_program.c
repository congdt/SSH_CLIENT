#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>		// errno

#include "ssh.h"
#include "key-exchange.h"
#include "sshbuf.h"

// socket(), recv(), connect(), setsockopt(), getaddrinfo(), inet_addr()
#include <sys/types.h>	
// socket(), recv(), connect(), setsockopt(), getaddrinfo()
#include <sys/socket.h>	
#include <netinet/in.h>	// inet_addr()
#include <arpa/inet.h>	// inet_addr()
#include <netdb.h>		// getaddrinfo()


#define PORT 22
#define BUFF_SIZE 2048

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;

char user[100];
char server[20];

int validateUser(char *str)
{
	int i;
	for(i=0; i < strlen(str); i++){
		if(str[i] == '@') break;
		if(i < 100-1)
			user[i] = str[i]; 
		else
			return 1;
	}
	if(i == strlen(str))
		return 1;
	else{
		user[i] = '\0';
	}
	printf("user: %s\n", user);
	int j;
	i++;
	for(j = i; j < strlen(str); j++){
		if(j - i < 20-1)
			server[j-i] = str[j];
		else 
			return 1;
	}
	server[j-i] = '\0';
	printf("server address: %s\n", server);
	return 0;
}

int validateArgs(int argc, char **argv)
{
	int i;

	if(argc != 2)
		return 0;
	if(strcmp(argv[1], "key-gen") == 0){
		return 2;
	}
	else {
		if(validateUser(argv[1])){
			printf("user or server addr is wrong\n");
			return 0;
		}
		
	}
	return 1;
}

int transportLayer();
int algoNegotiation();

int main(int argc, char **argv)
{
	
	int ret = validateArgs(argc, argv);
	if(ret == 0){
		printf("Argument's not supported\n");
		return 1;
	}
	else if(ret == 2){
		
		return 0;
	}
	else if(ret == 1){
   		transportLayer();
   	}
   	
   	return 0;
}

int transportLayer()
{
	int sockfd;
    int tv = 1000; // time-out
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)(&tv), sizeof(int));
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(server);
    serverAddr.sin_port = htons(PORT);
    
    if(connect(sockfd, (sockaddr*)(&serverAddr), sizeof(serverAddr))){
    	printf("connect error code: %d\n", errno);
    	return 1;
    }
   		
   		
 	// handle connection -------------------------------------------------
   	char buff[BUFF_SIZE];
	int ret;	
   	
   	// exchange protocol
   	char *protocol = "SSH-2.0-OpenSSH_6.6.1p1\r\n";
   	
   	if(send(sockfd, protocol, strlen(protocol), 0) == -1){
   		printf("Send error code %d", errno);
   		return 1;
   	}
   	ret = recv(sockfd, buff, BUFF_SIZE-1, 0);
   	if(ret == 0 ){
   		printf("Server shutdown\n");
   		return 1;
   	}
   	else if(ret == -1){
   		printf("receive error code: %d", errno);
   		return 1;
   	}
   	buff[ret] = '\0';
   	printf("From server: %s", buff);
	
	// key exchange init
	SSH_BUF *sshbuf = create_sshbuf();
	KEY_EXCHANGE_INIT key_ex;
	int i;
	
	key_ex.msgtype = SSH2_MSG_KEXINIT;
	//key_ex.cookie = {1, 2, 3, 4, 5, 6, 7, 8,8,7,6,5,4,3,2,1};
	for(i = 0; i < 16; i++){
		key_ex.cookie[i] = i;
	}
	key_ex.key_algo = "diffie-hellman-group-exchange-sha1";
	key_ex.s_key_algo = "ssh-rsa";
	key_ex.enc_algo_ctos = "aes256-ctr, aes256-cbc";
	key_ex.enc_algo_stoc = "aes256-ctr, aes256-cbc";
	key_ex.mac_algo_ctos = "hmac-sha1 hmac-sha2-256";
	key_ex.mac_algo_stoc = "hmac-sha1 hmac-sha2-256";
	key_ex.com_algo_ctos = "none,zlib";
	key_ex.com_algo_stoc = "none, zlib";
	key_ex.lan_ctos = "";
	key_ex.lan_stoc = "";
	key_ex.first_key = 0;
	key_ex.use_in_future = 0;
	
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
	
	unsigned int packet_length;
	unsigned char padding_length;
	unsigned char random_padding_size;
	
	padding_length = 8 -((sshbuf->length + sizeof(packet_length) + sizeof(padding_length)) % 8);
	packet_length = padding_length + sshbuf->length + 1;
	SSH_BUF *sshbuf2 = create_sshbuf();
	
	put_uint32_to_sshbuf(sshbuf2, packet_length);
	put_byte_to_sshbuf(sshbuf2, padding_length);
	
	// put payload
	put_byte_to_sshbuf(sshbuf, key_ex.msgtype);
	for(i = 0; i < 16; i++){
		put_byte_to_sshbuf(sshbuf, key_ex.cookie[i]);
	}
	put_string_to_sshbuf(sshbuf2, key_ex.key_algo);
	put_string_to_sshbuf(sshbuf2, key_ex.s_key_algo);
	put_string_to_sshbuf(sshbuf2, key_ex.enc_algo_ctos);
	put_string_to_sshbuf(sshbuf2, key_ex.enc_algo_stoc);
	put_string_to_sshbuf(sshbuf2, key_ex.mac_algo_ctos);
	put_string_to_sshbuf(sshbuf2, key_ex.mac_algo_stoc);
	put_string_to_sshbuf(sshbuf2, key_ex.com_algo_ctos);
	put_string_to_sshbuf(sshbuf2, key_ex.com_algo_stoc);
	put_string_to_sshbuf(sshbuf2, key_ex.lan_ctos);
	put_string_to_sshbuf(sshbuf2, key_ex.lan_stoc);
	put_uint32_to_sshbuf(sshbuf2, key_ex.use_in_future);
	
	// put random padding
	for(i = 0; i < padding_length; i++){
		put_byte_to_sshbuf(sshbuf2, (unsigned char)i);
	}
	
	
	send(sockfd, sshbuf2->buf, sshbuf2->length, 0);
	reset_sshbuf(sshbuf2);
	sshbuf2->length = MAX_LENGTH;
	sshbuf2->length = recv(sockfd, sshbuf2->buf, MAX_LENGTH -1, 0);
	
	printf("RECEIVE : %d", sshbuf2->length);
	
	get_uint32_from_sshbuf(sshbuf2, &packet_length);
	get_byte_from_sshbuf(sshbuf2, &padding_length);
	
	// get payload
	get_byte_from_sshbuf(sshbuf2, &key_ex.msgtype);
	for(i = 0; i < 16; i++){
		get_byte_from_sshbuf(sshbuf2, (unsigned char*)&key_ex.cookie[i]);
	}
	
	//key_ex.msgtype = SSH2_MSG_KEXINIT;
	//key_ex.cookie = (unsigned char *)malloc(500);
	key_ex.key_algo = (unsigned char *)malloc(500);
	key_ex.s_key_algo = (unsigned char *)malloc(500);
	key_ex.enc_algo_ctos = (unsigned char *)malloc(500);
	key_ex.enc_algo_stoc = (unsigned char *)malloc(500);
	key_ex.mac_algo_ctos = (unsigned char *)malloc(500);
	key_ex.mac_algo_stoc = (unsigned char *)malloc(500);
	key_ex.com_algo_ctos = (unsigned char *)malloc(500);
	key_ex.com_algo_stoc = (unsigned char *)malloc(500);
	key_ex.lan_ctos = (unsigned char *)malloc(500);
	key_ex.lan_stoc = (unsigned char *)malloc(500);
	
	
	get_string_from_sshbuf(sshbuf2, key_ex.key_algo, 500);
	get_string_from_sshbuf(sshbuf2, key_ex.s_key_algo, 500);
	get_string_from_sshbuf(sshbuf2, key_ex.enc_algo_ctos,500);
	get_string_from_sshbuf(sshbuf2, key_ex.enc_algo_stoc,500);
	get_string_from_sshbuf(sshbuf2, key_ex.mac_algo_ctos,500);
	get_string_from_sshbuf(sshbuf2, key_ex.mac_algo_stoc,500);
	get_string_from_sshbuf(sshbuf2, key_ex.com_algo_ctos,500);
	get_string_from_sshbuf(sshbuf2, key_ex.com_algo_stoc,500);
	get_string_from_sshbuf(sshbuf2, key_ex.lan_ctos,500);
	get_string_from_sshbuf(sshbuf2, key_ex.lan_stoc,500);
	get_byte_from_sshbuf(sshbuf2, &key_ex.first_key);
	get_uint32_from_sshbuf(sshbuf2, &key_ex.use_in_future);
	
	/* get random padding
	for(i = 0; i < padding_length; i++){
		get_byte_to_sshbuf(sshbuf2, i);
	}
	*/
	
	printf("1.%s\n2.%s\n3.%s\n4.%s\n5.%s\n6.%s\n7.%s\n8.%s\n9.%s\n10.%s", key_ex.key_algo, key_ex.s_key_algo, key_ex.enc_algo_ctos, key_ex.enc_algo_stoc, key_ex.mac_algo_ctos, key_ex.mac_algo_stoc, key_ex.com_algo_ctos, key_ex.com_algo_stoc, key_ex.lan_ctos, key_ex.lan_stoc);
	return 0;
}

int algoNegotiation()
{
	return 0;
}

