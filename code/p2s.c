/*
 * $Id: p2s.c,v 1.1 2002/05/16 19:15:39 raptor Exp $
 *
 * prism2stumbler v0.2 - WLAN Network Stumbler for PRISM2
 * Copyright (c) 2002 Raptor <raptor@0xdeadbeef.eu.org>
 *
 * Prism2stumbler is a WLAN Network Stumbler for wireless 
 * cards based on the PRISM2 chipset, running on console.
 * It only works on Linux (please note that wlan-ng drivers 
 * are required to activate PRISM2 built-in monitor mode).
 *
 * Tested with DLink DWL-650 NIC on Slackware Linux 8.0 
 * (both kernel releases 2.2.x and 2.4.x are supported, use 
 * it with wlan-ng 0.1.13, it may not work with 0.1.14).
 *
 * Based on prismstumbler.c code by synack (thank you!).
 * Thanks also to the prismstumbler project on Source Forge.
 *
 * This is development code. FOR EDUCATIONAL PURPOSES.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/ioctl.h>


#define SOUND
//#undef SOUND

#define MAX_BUFFER_SIZE 	4000
#define DEVNAME_LEN 		16
#define __WLAN_ATTRIB_PACK__	__attribute__ ((packed))
#define MCAST_GRP_SNIFF 	0x00000002	/* Used to notify Netlink */
#define P80211_IOCTL_MAGIC      (0x4a2d464dUL)	/* Voodoo magic */
#define MSG_BUFF_LEN            4000
#define P80211_IFREQ            (SIOCDEVPRIVATE + 1)
#define P80211DID_INVALID       0xffffffffUL

/* Don't change */
static unsigned int stop_sniffing = 0;


/* Packet Types */
#define MGT_PROBE           	0x0040		/* Client ProbeRequest */
#define MGT_PROBE_RESP          0x0050       	/* AP ProbeReponse */
#define MGT_ASSOC_REQ        	0x0000     	/* Client Assocrequest */
#define MGT_BEACON           	0x0080       	/* Management - Beacon frame */

#define FLAG_TO_DS              0x01
#define FLAG_FROM_DS            0x02
#define FLAG_WEP                0x10

#define IS_TO_DS(x)            	((x) & FLAG_TO_DS)
#define IS_FROM_DS(x)          	((x) & FLAG_FROM_DS)
#define IS_WEP(x)              	((x) & FLAG_WEP)


/* ************************************************************************* */
/*        Logical field codes (IEEE 802.11 encoding of tags)                 */
/* ************************************************************************* */
#define TAG_SSID           	0x00
#define TAG_SUPP_RATES     	0x01
#define TAG_FH_PARAMETER   	0x02
#define TAG_DS_PARAMETER   	0x03
#define TAG_CF_PARAMETER   	0x04
#define TAG_TIM            	0x05
#define TAG_IBSS_PARAMETER 	0x06
#define TAG_CHALLENGE_TEXT 	0x10


#define CHANNEL_READ_COUNT 3	/* Max number of pkts to be read for channel */	


/* Request struct */
typedef struct p80211ioctl_req
{
        char name[16] __attribute__ ((packed));
        void *data __attribute__ ((packed));                
        __u32 magic __attribute__ ((packed));                
        __u16 len __attribute__ ((packed));               
        __u32 result __attribute__ ((packed));               
} p80211ioctl_req_t;
                                        
/* Message struct */
typedef struct p80211msg
{
  	__u32 msgcode __attribute__ ((packed));
  	__u32 msglen __attribute__ ((packed));
  	__u8 devname[DEVNAME_LEN] __attribute__ ((packed));
  	__u8 args[0] __attribute__ ((packed));
} p80211msg_t;
                        
/* Basic information types in the sniffed packet */
typedef struct {
  	__u32 did __attribute__ ((packed));
  	__u16 status __attribute__ ((packed));
  	__u16 len __attribute__ ((packed));
  	__u32 data __attribute__ ((packed));
} p80211item_t;

/*
 * Just before the payload, the prismcard puts in a lot 
 * of other infos, like signal quality and similar stuff
 */
typedef struct {
  	__u32 msgcode __attribute__ ((packed));
  	__u32 msglen __attribute__ ((packed));
  	__u8 devname [DEVNAME_LEN] __attribute__ ((packed));
  	p80211item_t hosttime __attribute__ ((packed));
  	p80211item_t mactime __attribute__ ((packed));
  	p80211item_t channel __attribute__ ((packed));
  	p80211item_t rssi __attribute__ ((packed));
  	p80211item_t sq __attribute__ ((packed));
  	p80211item_t signal __attribute__ ((packed));
  	p80211item_t noise __attribute__ ((packed));
  	p80211item_t rate __attribute__ ((packed));
  	p80211item_t istx __attribute__ ((packed));
  	p80211item_t frmlen __attribute__ ((packed));
} AdmInfo_t;

/* Overlay to directly index various types of data in Mgmt Frames */
typedef struct {
	unsigned short frametype;
	unsigned short duration;
	unsigned char DestAddr[6];
	unsigned char SrcAddr[6];
	unsigned char BssId[6];
	unsigned short FragSeq;
        unsigned short TimeStamp[4];
	unsigned short BeaconInterval;
	unsigned short Capabilities;
} FixedMgmt_t;

typedef struct {
	unsigned short frametype;
	unsigned short duration;
	unsigned char DestAddr[6];
	unsigned char SrcAddr[6];
	unsigned char BssId[6];
	unsigned short FragSeq;
} ProbeFixedMgmt_t;

typedef struct {
	char DestMac[20];
	char SrcMac[20];
	char BssId[20];
	char SSID[80];
	int hasWep;
	int isAp;
	int Channel;
	int Signal;
        int Noise;
        int FrameType;
} ScanResult_t;


/* Use globals, ugly but efficient */
static int RawSock;
static struct sockaddr_nl nl_sk_addr;
static ScanResult_t Res;

char *devname="wlan0";	/* Scan on this device */
//int debug = 0;

__u8 Channel = 0;
__u8 message[MSG_BUFF_LEN];
__u32 msgcode = P80211DID_INVALID;  


/* Function prototypes */
int getPacket(unsigned char *buf, int maxlen, int timeout);
void closePacket(void);
int openPacket(void);
int processPacket(unsigned char *packet, int len, int RealChannel);
void stop_signal();
void fatalerr(char *pattern, ...);
int sniff(__u8 channel);
/* Prototypes end */


int main (int argc, char **argv) {
	
	int recvlen;
	unsigned char msgbuf[MAX_BUFFER_SIZE];
	int MaxPackPerChannel;
	struct tm *t;
	time_t now, last_time;
	int Time_Add;
	char prevSSID[80], lt[50];
	int result = 0;

/* Setup and signal handling */
	setvbuf(stdout, NULL, _IONBF, 0);	/* Disable stdout buffering */
	setpriority(PRIO_PROCESS, 0, -20);
	signal(SIGINT, stop_signal);
	fprintf(stderr, "Use CTRL-C to stop sniffing\n");

/* Open Netlink device */
	if (openPacket() < 0)			/* Error (Netlink) */
		fatalerr("err: can't open netlink socket");
	
/* Timer settings */
	time(&last_time);
	Time_Add = 0;
    
/* Main loop */
	while (!stop_sniffing) {
        
/* Scan the channels (1-14) */
		Channel++;
		if (Channel > 14) Channel = 1;
		fprintf(stdout, "Channel: (%2.d)        \r", Channel);
		//printf("Channel=%d\n", Channel);
	
		if (sniff(Channel) != 0)	/* Error (sniff) */
			fatalerr("err: socket or wlanctl-ng problem");
	     
		MaxPackPerChannel = CHANNEL_READ_COUNT;

		do {
/* Initialise buffer and start sniffing */
			memset(msgbuf, 0, MAX_BUFFER_SIZE);
			recvlen = getPacket(msgbuf, MAX_BUFFER_SIZE, 50);

			if (recvlen < 0) break;  	/* Error reading pkts */
			if (recvlen == 0) break;  	/* Nothing to read */

/* We got something, do we? */
			if (processPacket(msgbuf, recvlen, Channel)) {

				if (Res.Channel < 1 || Res.Channel > 14 )
				 	continue; 	/* Bogus packet */
				
/* Timing management */
				time(&now);
				t = (struct tm *)localtime(&now);
				strftime(lt, sizeof(lt)-1, "%d/%m %H:%M:%S", t);
				if (now == last_time)
					Time_Add++;
				else {
					last_time = now;
					Time_Add = 0;
				}
						
/* Print collected informations */
				printf("[%s (%.2d)]  SSID=\"%s\" CH=%d WEP=%d AP=%d SIG=%.3d:%.3d  SRC=%s DST=%s BSSID=%s\n", lt, Time_Add, Res.SSID, Res.Channel, Res.hasWep, Res.isAp, Res.Signal, Res.Noise, Res.SrcMac, Res.DestMac, Res.BssId);
				
/* Sound signal (if is another SSID) */
				if (strcmp(prevSSID, Res.SSID)) {
#ifdef SOUND
					system("echo -en '\007'");
			   		//system("/usr/bin/play bweep.wav");
#endif
				}
				strcpy(prevSSID, Res.SSID);
				fflush(stdout);
			}

		} while (--MaxPackPerChannel > 0 ); /* Until we read enough */
		
	} /* While still sniffing */

/* Close all and exit */
	closePacket();
	exit(0);
}


/* Open Netlink device */
int openPacket(void) {

	if ((RawSock = socket (PF_NETLINK, SOCK_RAW, MCAST_GRP_SNIFF)) < 0)
	      	return(-1); 

	memset(&nl_sk_addr, 0, sizeof(struct sockaddr_nl));
	nl_sk_addr.nl_family = (sa_family_t)PF_NETLINK;
	nl_sk_addr.nl_pid = (unsigned int)getpid();

	nl_sk_addr.nl_groups = MCAST_GRP_SNIFF;

	if ( bind(RawSock, (struct sockaddr *)&nl_sk_addr, 
		sizeof(struct sockaddr_nl) ) < 0)
		return(-1);

	return(RawSock);
}


/* Close Netlink device */
void closePacket() {
	close(RawSock);
}


/* Get packets from Netlink device */
int getPacket(unsigned char *buf, int maxlen, int timeout) {
	fd_set rs;
	int r;
	struct timeval tm;
	struct timeval *ptm;

	FD_ZERO(&rs);
	FD_SET(RawSock, &rs);
	if (timeout >= 0) {
		tm.tv_sec = timeout / 1000;
		tm.tv_usec = (timeout % 1000) * 1000;
		ptm = &tm;
	} else {
		ptm = NULL;
	}
	r = select(RawSock + 1, &rs, NULL, NULL, ptm);

	if (r < 0) { 
		perror("select");	/* FYI */
		return(-1);
	}

	if ( (r == 0) && (timeout >= 0) ) { 
		/* printf("Timeout\n"); */  
		return(0);
	}

	if (FD_ISSET(RawSock, &rs)) {
		r = recv(RawSock, buf, maxlen, 0);

		if (r < 0) { 
			perror("recv"); /* FYI */
			return(-1);
		}

		return(r);
	}

	return(0); /* Noting to read */
}


/* Get the different data from the Mgmt header. Fill global struct */
int processPacket(unsigned char *packet, int len, int RealChannel) {
	FixedMgmt_t *M;
	ProbeFixedMgmt_t *P;
	AdmInfo_t *A; 
  	
	unsigned char *admbits, *fixbits, *varBits;
	int i;
	int tagType, tagLen;
	unsigned char TextBuff[256];

	admbits = packet;
	fixbits = &packet[sizeof(AdmInfo_t)]; 	/* Here starts the payload */

	A = (AdmInfo_t *)admbits; 		/* First the frame from card */
	M =  (FixedMgmt_t *) fixbits; 		/* ...then the actual data */
	P =  (ProbeFixedMgmt_t *) fixbits;

	memset(&Res, 0, sizeof(Res));

	Res.FrameType = M->frametype;
	
	if (M->frametype == MGT_PROBE_RESP || M->frametype == MGT_BEACON) { 
		Res.isAp = IS_TO_DS(M->Capabilities) != 0;
		Res.hasWep = IS_WEP(M->Capabilities) != 0;
	}

	if (M->frametype == MGT_PROBE || M->frametype == MGT_BEACON) { 
		if (  !(M->DestAddr[0] == 0xff && M->DestAddr[1] == 0xff &&
			M->DestAddr[2] == 0xff && M->DestAddr[3] == 0xff &&
			M->DestAddr[4] == 0xff && M->DestAddr[5] == 0xff) )  
				return(0);
	}

	if (M->frametype == MGT_PROBE) { 
		Res.isAp = 3;
		Res.hasWep = 0;
		Res.Channel = RealChannel;
	}

	sprintf(Res.DestMac, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		M->DestAddr[0], M->DestAddr[1],
		M->DestAddr[2], M->DestAddr[3],
		M->DestAddr[4], M->DestAddr[5]);

	sprintf(Res.SrcMac, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		M->SrcAddr[0], M->SrcAddr[1],
		M->SrcAddr[2], M->SrcAddr[3],
		M->SrcAddr[4], M->SrcAddr[5]);

	sprintf(Res.BssId, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		M->BssId[0], M->BssId[1],
		M->BssId[2], M->BssId[3],
		M->BssId[4], M->BssId[5]);

	Res.Signal = A->signal.data;
	Res.Noise = A->noise.data;


	if (M->frametype == MGT_PROBE) {
		if (len <= sizeof(ProbeFixedMgmt_t)) return 0;

		varBits = &fixbits[sizeof(ProbeFixedMgmt_t)];

	} else { /* Beacon and Probe Response */
		if( len <= sizeof(FixedMgmt_t) ) return 0;

		varBits = &fixbits[sizeof(FixedMgmt_t)];
	}

/* Get the tagged values (type+length+data) */
	while (varBits < (packet + len)) {

		tagType = varBits[0]; 
		tagLen = varBits[1];
		varBits += 2;
	
		switch(tagType){

			case TAG_SSID:
					strncpy(Res.SSID, varBits, tagLen);
					break;

			case TAG_DS_PARAMETER:
					if (tagLen == 1) Res.Channel = *varBits;
					break;

			/* Skip all other values for the moment */
			case TAG_SUPP_RATES:
			case TAG_FH_PARAMETER:
			case TAG_CF_PARAMETER:
			case TAG_TIM:
			case TAG_IBSS_PARAMETER:
			case TAG_CHALLENGE_TEXT:	

					 break;
		}	

		varBits += tagLen;
	}

	return(1);
}


/* Signal handler */
void stop_signal() 
{
	fprintf(stderr, "Received CTRL-C - sniffing aborted\n");
  	stop_sniffing = 1;
}


/* Error handling routine */
void fatalerr(char *pattern, ...)
{
        va_list ap;
        va_start(ap, pattern);

        fprintf(stderr, "p2s-");
        vfprintf(stderr, pattern, ap);
        fprintf(stderr, " (exit forced).\n\n");

        va_end(ap);

        exit(-1);
}


/* The sniffer core */
int sniff(__u8 channel)
{
	p80211msg_t *msgp = (p80211msg_t *)message;
	int i;
	int bodylen;
	int result = -1;
	int fd;
	p80211ioctl_req_t req;
	
/* pHEAR */
        __u8 body[36] = "\x83\x10\x00\x00"
        		"\x00\x00\x04\x00" 
        		"\x01\x00\x00\x00" 
        		"\x83\x20\x00\x00"
        		"\x00\x00\x04\x00" 
        		"\x01\x00\x00\x00"
        		"\x83\x30\x00\x00" 
        		"\x01\x00\x04\x00" 
        		"\x00\x00\x00\x00";
        		  
	msgp->msgcode = 0x00000083;
	msgp->msglen = 0x0000003c;
	strcpy(msgp->devname, devname);
	
	for ( i = 0; i < 36; i += 4 ) {
		msgp->args[i]   = body[i];
	    	msgp->args[i+1] = body[i+1];
	    	msgp->args[i+2] = body[i+2];
	    	msgp->args[i+3] = body[i+3]; 
	}    
	
	msgp->args[20] = channel;
	
	/* Use the Magic */
	req.magic = P80211_IOCTL_MAGIC;

	/* Get a socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return(result);
	
	req.len = MSG_BUFF_LEN;		
	req.data = message;
	strcpy(req.name, devname);
	req.result = 0;

	result = ioctl(fd, P80211_IFREQ, &req);
	
	close(fd);
	return(result);	/* result may be -1 (wlan-ng error) */
}
