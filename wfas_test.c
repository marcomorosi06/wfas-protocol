#define _DEFAULT_SOURCE
#include "wfas.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define STREAM_PORT 9090
#define SR 48000
#define CH 2
#define FPP 240
#define WPI 3.14159265358979323846

static const char *g_key = NULL;
static double g_phase = 0.0;

static long now_ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000L+t.tv_nsec/1000000L;}
static void msleep(long ms){struct timespec t;t.tv_sec=ms/1000;t.tv_nsec=(ms%1000)*1000000L;nanosleep(&t,NULL);}
static void sendto_(int s,const struct sockaddr_in*a,const void*b,size_t l){sendto(s,b,l,0,(const struct sockaddr*)a,sizeof *a);}
static void gen_nonce(char out[WFAS_NONCE_HEX+1]){unsigned char b[WFAS_NONCE_BYTES];FILE*f=fopen("/dev/urandom","rb");size_t i;if(f){if(fread(b,1,sizeof b,f)!=sizeof b)for(i=0;i<sizeof b;i++)b[i]=(unsigned char)rand();fclose(f);}else for(i=0;i<sizeof b;i++)b[i]=(unsigned char)rand();const char*h="0123456789abcdef";for(i=0;i<sizeof b;i++){out[i*2]=h[b[i]>>4];out[i*2+1]=h[b[i]&15];}out[WFAS_NONCE_HEX]=0;}
static void fill_tone(int16_t*p,int fr){double st=2.0*WPI*440.0/SR;int i,c;for(i=0;i<fr;i++){int16_t s=(int16_t)(sin(g_phase)*8000.0);for(c=0;c<CH;c++)p[i*CH+c]=s;g_phase+=st;if(g_phase>2*WPI)g_phase-=2*WPI;}}

static int selftest(void){
    uint8_t key[20],mac[32];char hex[65];memset(key,0x0b,20);
    wfas_hmac_sha256(key,20,(const uint8_t*)"Hi There",8,mac);
    const char*h="0123456789abcdef";int i;for(i=0;i<32;i++){hex[i*2]=h[mac[i]>>4];hex[i*2+1]=h[mac[i]&15];}hex[64]=0;
    const char*exp="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    printf("HMAC-SHA256 RFC4231 TC1: %s\n", strcmp(hex,exp)==0?"OK":"FAIL");
    char cp[WFAS_PROOF_HEX+1],sp[WFAS_PROOF_HEX+1];
    wfas_auth_proof("secret",'S',"aaaa","bbbb",sp);
    wfas_auth_proof("secret",'C',"aaaa","bbbb",cp);
    printf("domain separation (S != C): %s\n", wfas_proof_equal(sp,cp)?"FAIL":"OK");
    return strcmp(hex,exp)==0 && !wfas_proof_equal(sp,cp) ? 0 : 1;
}

static int run_server(void){
    int s=socket(AF_INET,SOCK_DGRAM,0);if(s<0){perror("socket");return 1;}
    int yes=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    struct sockaddr_in loc;memset(&loc,0,sizeof loc);loc.sin_family=AF_INET;loc.sin_addr.s_addr=htonl(INADDR_ANY);loc.sin_port=htons(STREAM_PORT);
    if(bind(s,(struct sockaddr*)&loc,sizeof loc)<0){perror("bind");return 1;}
    printf("[server] UDP %d  auth=%s\n",STREAM_PORT, g_key?"key":"off");
    int16_t pcm[FPP*CH];uint8_t pkt[WFAS_MTU];char rx[1024];
    for(;;){
        struct sockaddr_in cl;socklen_t cn;int connected=0;char snonce[WFAS_NONCE_HEX+1];
        char pend_cnonce[WFAS_NONCE_HEX+1]="",pend_snonce[WFAS_NONCE_HEX+1]="";
        printf("[server] waiting...\n");
        while(!connected){
            struct timeval tv={1,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
            cn=sizeof cl;ssize_t n=recvfrom(s,rx,sizeof rx-1,0,(struct sockaddr*)&cl,&cn);
            if(n<=0)continue;
            rx[n]=0;
            while(n>0&&(rx[n-1]=='\n'||rx[n-1]=='\r'||rx[n-1]==' '))rx[--n]=0;
            wfas_packet_type t=wfas_classify((const uint8_t*)rx,(size_t)n);
            if(t==WFAS_PKT_MODE_PROBE){sendto_(s,&cl,WFAS_MSG_UNICAST,strlen(WFAS_MSG_UNICAST));continue;}
            if(t!=WFAS_PKT_HELLO)continue;
            if(!g_key){char ack[16];snprintf(ack,sizeof ack,"%s;v=%d",WFAS_MSG_HELLO_ACK,WFAS_PROTOCOL_VERSION);sendto_(s,&cl,ack,strlen(ack));printf("[server] connected %s\n",inet_ntoa(cl.sin_addr));connected=1;continue;}
            char cproof[WFAS_PROOF_HEX+1];int has=wfas_get_token(rx,"cproof",cproof,sizeof cproof);
            char cnonce[WFAS_NONCE_HEX+1];wfas_get_token(rx,"cnonce",cnonce,sizeof cnonce);
            if(!has){ gen_nonce(snonce);char sp[WFAS_PROOF_HEX+1];wfas_auth_proof(g_key,'S',cnonce,snonce,sp);
                memcpy(pend_cnonce,cnonce,WFAS_NONCE_HEX+1);memcpy(pend_snonce,snonce,WFAS_NONCE_HEX+1);
                char m[160];snprintf(m,sizeof m,"%s;snonce=%s;sproof=%s",WFAS_MSG_AUTH_REQUIRED,snonce,sp);sendto_(s,&cl,m,strlen(m));
                printf("[server] challenge sent\n");continue; }
            char exp[WFAS_PROOF_HEX+1];wfas_auth_proof(g_key,'C',pend_cnonce[0]?pend_cnonce:cnonce,pend_snonce,exp);
            if(wfas_proof_equal(cproof,exp)){char ack[16];snprintf(ack,sizeof ack,"%s;v=%d",WFAS_MSG_HELLO_ACK,WFAS_PROTOCOL_VERSION);sendto_(s,&cl,ack,strlen(ack));printf("[server] AUTH OK, connected %s\n",inet_ntoa(cl.sin_addr));connected=1;}
            else{sendto_(s,&cl,WFAS_MSG_UNAUTHORIZED,strlen(WFAS_MSG_UNAUTHORIZED));printf("[server] AUTH FAIL -> unauthorized\n");}
        }
        wfas_sender tx;wfas_sender_init(&tx);long lp=now_ms(),tg=now_ms();int alive=1;
        while(alive){fill_tone(pcm,FPP);int ln=wfas_build_audio(&tx,pkt,sizeof pkt,pcm,FPP,CH);if(ln>0)sendto_(s,&cl,pkt,(size_t)ln);
            if(now_ms()-lp>=1000){sendto_(s,&cl,WFAS_MSG_PING,strlen(WFAS_MSG_PING));lp=now_ms();}
            struct sockaddr_in fr;socklen_t fl=sizeof fr;ssize_t n=recvfrom(s,rx,sizeof rx-1,MSG_DONTWAIT,(struct sockaddr*)&fr,&fl);
            if(n>0){rx[n]=0;if(wfas_classify((const uint8_t*)rx,(size_t)n)==WFAS_PKT_CLIENT_BYE){printf("[server] bye\n");alive=0;}}
            tg+=1000L*FPP/SR;long d=tg-now_ms();if(d>0)msleep(d);else tg=now_ms();}
    }
}

static int run_client(const char*ip){
    int s=socket(AF_INET,SOCK_DGRAM,0);if(s<0){perror("socket");return 1;}
    struct sockaddr_in srv;memset(&srv,0,sizeof srv);srv.sin_family=AF_INET;srv.sin_port=htons(STREAM_PORT);
    if(inet_pton(AF_INET,ip,&srv.sin_addr)!=1){fprintf(stderr,"[client] bad ip\n");return 1;}
    struct timeval tv={1,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    char cnonce[WFAS_NONCE_HEX+1];gen_nonce(cnonce);
    char hello[160];snprintf(hello,sizeof hello,"%s;v=%d;cnonce=%s",WFAS_MSG_HELLO,WFAS_PROTOCOL_VERSION,cnonce);
    char rx[1024];int connected=0,proved=0;long start=now_ms();
    fprintf(stderr,"[client] connecting to %s  auth=%s\n",ip,g_key?"key":"off");
    while(!connected && now_ms()-start<15000){
        sendto_(s,&srv,hello,strlen(hello));
        ssize_t n=recvfrom(s,rx,sizeof rx-1,0,NULL,NULL);if(n<=0)continue;rx[n]=0;
        wfas_packet_type t=wfas_classify((const uint8_t*)rx,(size_t)n);
        if(t==WFAS_PKT_HELLO_ACK){ if(g_key&&!proved){fprintf(stderr,"[client] ABORT: server skipped auth (possible downgrade)\n");return 1;} connected=1; }
        else if(t==WFAS_PKT_AUTH_REQUIRED){ if(!g_key){fprintf(stderr,"[client] server requires a key (use --key)\n");return 1;}
            char sn[WFAS_NONCE_HEX+1],sp[WFAS_PROOF_HEX+1];wfas_get_token(rx,"snonce",sn,sizeof sn);wfas_get_token(rx,"sproof",sp,sizeof sp);
            char es[WFAS_PROOF_HEX+1];wfas_auth_proof(g_key,'S',cnonce,sn,es);
            if(!wfas_proof_equal(sp,es)){fprintf(stderr,"[client] ABORT: server proof invalid (rogue server or wrong key)\n");return 1;}
            char cp[WFAS_PROOF_HEX+1];wfas_auth_proof(g_key,'C',cnonce,sn,cp);
            snprintf(hello,sizeof hello,"%s;v=%d;cnonce=%s;cproof=%s",WFAS_MSG_HELLO,WFAS_PROTOCOL_VERSION,cnonce,cp);proved=1;
            fprintf(stderr,"[client] server authenticated, sending proof\n"); }
        else if(t==WFAS_PKT_UNAUTHORIZED){fprintf(stderr,"[client] UNAUTHORIZED (wrong key or denied)\n");return 1;}
    }
    if(!connected){fprintf(stderr,"[client] no/failed response\n");return 1;}
    fprintf(stderr,"[client] connected, receiving...\n");
    long lp=now_ms(),ls=now_ms(),t0=now_ms();long au=0,by=0;int run=1;
    while(run){ssize_t n=recvfrom(s,rx,sizeof rx,0,NULL,NULL);long no=now_ms();
        if(n>0){wfas_packet_type t=wfas_classify((const uint8_t*)rx,(size_t)n);
            if(t==WFAS_PKT_AUDIO){wfas_header h;const uint8_t*pc;size_t pl;if(wfas_parse_audio((const uint8_t*)rx,(size_t)n,&h,&pc,&pl)==0){au++;by+=(long)pl;}}
            else if(t==WFAS_PKT_PING)lp=no; else if(t==WFAS_PKT_BYE){run=0;}}
        if(no-lp>3000){fprintf(stderr,"[client] timeout\n");run=0;}
        if(no-ls>=1000){double sec=(no-t0)/1000.0;fprintf(stderr,"[client] audio=%ld bytes=%ld %.0f kbit/s\n",au,by,sec>0?(by*8.0/1000.0)/sec:0);ls=no;}}
    sendto_(s,&srv,WFAS_MSG_CLIENT_BYE,strlen(WFAS_MSG_CLIENT_BYE));return 0;
}

int main(int argc,char**argv){
    setvbuf(stdout,NULL,_IOLBF,0);
    int i;for(i=1;i<argc;i++){if(strcmp(argv[i],"--key")==0&&i+1<argc)g_key=argv[++i];}
    if(argc>=2&&strcmp(argv[1],"selftest")==0)return selftest();
    if(argc>=2&&strcmp(argv[1],"server")==0)return run_server();
    if(argc>=3&&strcmp(argv[1],"client")==0)return run_client(argv[2]);
    fprintf(stderr,"usage: %s selftest | server [--key K] | client <ip> [--key K]\n",argv[0]);return 2;
}
