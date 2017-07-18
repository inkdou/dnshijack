
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define DNS_ID           0
#define DNS_FLAGS        2
#define DNS_QUEST        4
#define DNS_ANS          6
#define DNS_AUTH         8
#define DNS_ADD         10

#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define OPCODE_SHIFT    11
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_CONFLICT      (1<<10)         /* conflict detected */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_TENTATIVE     (1<<8)          /* response is tentative */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_Z             (1<<6)          /* Z */
#define F_AUTHENTIC     (1<<5)          /* authentic data (RFC2535) */
#define F_CHECKDISABLE  (1<<4)          /* checking disabled (RFC2535) */
#define F_RCODE         (0xF<<0)        /* reply code */

#define pto16(p) ((unsigned short) \
                  ((unsigned short)*((unsigned char *)(p)+0) << 8 | \
                  (unsigned short)*((unsigned char *)(p)+1) << 0 )) 

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
    unsigned char *data1;
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned int iphl;
    unsigned int udphl;
    unsigned char *dnsdata;
    unsigned char *reqdata;
    unsigned char *ansaddr;
    unsigned char *ansdata;
    unsigned int i,reqnamelen;
    unsigned char reqlen;

    unsigned short dnsid,flags, opcode, rcode, quest, req, ans, auth, add;

    int ret;
	printf("entering callback\n");
    ret = nfq_get_payload(nfa, &data1);

    iph = (struct iphdr*)(data1);
    iphl = iph->ihl << 2; 
    printf("protocol %d\n", iph->protocol);
    if( 17 != iph->protocol)
        goto ACCEPT;

    udph = (struct udphdr*)(data1 + iphl);
    udphl = sizeof(struct udphdr);

    dnsdata = (unsigned char *)((unsigned char *)udph + udphl);

    dnsid = pto16(dnsdata + DNS_ID);
    flags = pto16(dnsdata + DNS_FLAGS);
    opcode = (unsigned short)((flags & F_OPCODE) >> OPCODE_SHIFT);
    rcode  = (unsigned short)(flags & F_RCODE);
    printf("id=0x%X, flags=0x%X, opcode=0x%X, rcode=0x%X\n", dnsid, flags, opcode, rcode);

    quest = flags & F_RESPONSE;   

    if(!quest) 
    {
        printf("request\n"); 
    }
    else {
        req = pto16(dnsdata + DNS_QUEST); //the number of req
        ans = pto16(dnsdata + DNS_ANS); //the number of ans
        printf("response, req=%d, ans=%d\n", req, ans); 
        if(ans <= 0)
            goto ACCEPT;
        else
        {
                
            //first; the offset of queries
            reqdata = dnsdata + 12;
            i = 0;
            while(*(reqdata + i++) != 0x00);
            reqnamelen = i;
            printf("reqnamelen = %d\n", reqnamelen);

            reqlen = reqnamelen + 4;

            ansdata = dnsdata + 12 + reqlen;
            ansaddr = ansdata + 2 +2 + 2 + 4 +2 ;

            ansaddr[3]= 0xc0;

            printf("0x%X,0x%X,0x%X,0x%X\n", ansaddr[0], ansaddr[1], ansaddr[2], ansaddr[3]);

            //checksum
            udph->check=0; //keep udp checksum happy
            //printf("udpchecksum=%d,\n", udph->check);  
            //nfq_udp_compute_checksum_ipv4(udph,iph); 
            //printf("udpchecksum=%d,\n", udph->check);  
	        return nfq_set_verdict(qh, id, NF_ACCEPT,ret, data1);
        }
    }

ACCEPT:
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	//struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
