/*	define all constant to use in ssh client
 */

#ifndef _SSH_H_
#define _SSH_H_


/* transport layer: generic */
#define SSH2_MSG_DISCONNECT				1
#define SSH2_MSG_IGNORE					2
#define SSH2_MSG_UNIMPLEMENTED			3
#define SSH2_MSG_DEBUG					4
#define SSH2_MSG_SERVICE_REQUEST		5
#define SSH2_MSG_SERVICE_ACCEPT			6
#define SSH2_MSG_EXT_INFO				7

/* transport layer: algorithm negotiation */

#define SSH2_MSG_KEXINIT				20
#define SSH2_MSG_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#define SSH2_MSG_KEXDH_INIT					30
#define SSH2_MSG_KEXDH_REPLY				31

/* dh-group-exchange */
#define SSH2_MSG_KEX_DH_GEX_REQUEST_OLD		30
#define SSH2_MSG_KEX_DH_GEX_GROUP			31
#define SSH2_MSG_KEX_DH_GEX_INIT			32
#define SSH2_MSG_KEX_DH_GEX_REPLY			33
#define SSH2_MSG_KEX_DH_GEX_REQUEST			34

/* ecdh */
#define SSH2_MSG_KEX_ECDH_INIT				30
#define SSH2_MSG_KEX_ECDH_REPLY				31

/* user authentication: generic */

#define SSH2_MSG_USERAUTH_REQUEST			50
#define SSH2_MSG_USERAUTH_FAILURE			51
#define SSH2_MSG_USERAUTH_SUCCESS			52
#define SSH2_MSG_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#define SSH2_MSG_USERAUTH_PK_OK					60
#define SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ		60
#define SSH2_MSG_USERAUTH_INFO_REQUEST			60
#define SSH2_MSG_USERAUTH_INFO_RESPONSE			61



extern int myErrorCode;

/*  ERROR CODE */
#define NO_ERROR 0

/* sshbuf.h */
#define ERROR_PUT_BYTE_TO_SSHBUF 1
#define ERROR_PUT_UINT32_TO_SSHBUF 2
#define ERROR_PUT_UINT64_TO_SSHBUF 3
#define ERROR_PUT_STRING_TO_SSHBUF 4
#define ERROR_PUT_BIGNUM_TO_SSHBUF 5

#define ERROR_GET_BYTE_FROM_SSHBUF 6
#define ERROR_GET_UINT32_FROM_SSHBUF 7
#define ERROR_GET_UINT64_FROM_SSHBUF 8
#define ERROR_GET_STRING_FROM_SSHBUF_1 9
#define ERROR_GET_STRING_FROM_SSHBUF_2 10
#define ERROR_GET_BIGNUM_FROM_SSHBUF 11

/* key-exchange.h */

#define ERROR_PUT_KEYINIT 17
#define ERROR_GET_KEYINIT 18



#endif
