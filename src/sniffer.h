
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/if_ether.h>
#include<arpa/inet.h>
#include<net/ethernet.h>

#include "help.h"
#include "tv.h"
#include "constants.h"

#include "dbg.h"
#include<pthread.h>

#define BUFFER_MAX 2048

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct t_arg {
	GtkWidget * tv;
	time_t lt_start;
	time_t lt_now;
	int * no;
	FILE * fp_index;
	FILE * fp_data;
	char * buf;
	int data_len;
	long * data_index;
};

typedef void(*handler)(GtkWidget * list, char * buf);

int get_proto_type(char * buf) {
	struct ether_header * p_eth_hdr;
	struct ip * p_ip_hdr;
	struct tcphdr * p_tcp_hdr;
	struct udphdr * p_udp_hdr;
	struct ether_arp * p_eth_arp;
	
	
	p_eth_hdr = (struct ether_header *)buf;
	
	/* 802.3 ethernet */
	if(0x0600 > ntohs(p_eth_hdr->ether_type))
		return PROTO_802_3;
	
	/* ARP */
	if(ETHERTYPE_ARP == ntohs(p_eth_hdr->ether_type)) {
	
		return PROTO_ARP;
		
	} 
	/* IP */
	else if(ETHERTYPE_IP == ntohs(p_eth_hdr->ether_type)){
	
		p_ip_hdr = (struct ip *)(buf + 14);
		
		/* ICMP */
		if(IPPROTO_ICMP == p_ip_hdr->ip_p) {	
		
			return PROTO_ICMP;			
			
		} 
		/* TCP */
		else if(IPPROTO_TCP == p_ip_hdr->ip_p) {
		
			p_tcp_hdr = (struct tcphdr *)(buf + 14 + p_ip_hdr->ip_hl * 4);
			if(ntohs(p_ip_hdr->ip_len) == p_ip_hdr->ip_hl * 4 + p_tcp_hdr->doff * 4)
				return PROTO_TCP;
			else {
				char * p = buf + 14 + p_ip_hdr->ip_hl * 4 + p_tcp_hdr->doff * 4;
				if(0 == str_cmp_cc("GET", p, 3, FALSE)) {
					return PROTO_HTTP;
				} else {
					return -1;
				}
			}
			
		} 
		/* UDP */
		else if(IPPROTO_UDP == p_ip_hdr->ip_p) {
		
			return PROTO_UDP;
			//p_udp_hdr = (struct udphdr *)(buf + 14 + p_ip_hdr->ip_hl * 4);
			
		} 
		/* Other IP based protocol */
		else return -1;
		
	} else {
		return -1;
	}
	
	
	
	
	
}
	
/* protocol aspect processes */

// arp
void proc_arp(GtkWidget * list, char * buffer, time_t lt_start, time_t lt_now, int no) {
	
	struct ether_header * p_eth_hdr;
	struct arphdr * p_arp_hdr;
	struct ip * p_ip_hdr;
	struct tcphdr * p_tcp_hdr;
	struct udphdr * p_udp_hdr;
	struct icmp * p_icmp_hdr;
	struct ether_arp * p_eth_arp;
	char info[100];
	char mac_src[18];
	char mac_dst[18];
	char ip_src[16];
	char ip_dst[16];
	int ar_op; 
	
	p_eth_hdr = (struct ether_header *)buffer;
	p_eth_arp = (struct ether_arp *)(buffer + 14);
	
	eth_ntop_cc(p_eth_hdr->ether_shost, mac_src);
	eth_ntop_cc(p_eth_hdr->ether_dhost, mac_dst);
	inet_ntop(AF_INET, p_eth_arp->arp_spa, ip_src, sizeof(ip_src));
	inet_ntop(AF_INET, p_eth_arp->arp_tpa, ip_dst, sizeof(ip_dst));
	
	ar_op = ntohs(p_eth_arp->ea_hdr.ar_op);
	
	if(ARPOP_REQUEST_CC == ar_op)
		sprintf(info, "Who has %s ? Tell %s", ip_dst, ip_src);
	else if(ARPOP_REPLY_CC == ar_op)
		sprintf(info, "%s is at %s", ip_src, mac_dst);
	else
		sprintf(info, "Opcode: %d", ar_op);
	
	add_to_list(
		list, 
		no, 
		(lt_now - lt_start)/1000.0, 
		mac_src, 
		mac_dst, 
		"ARP", 
		info,
		"#000000",
		"#d6e8ff");
}

// icmp
void proc_icmp(GtkWidget * list, char * buffer, time_t lt_start, time_t lt_now, int no) {
	
	struct ether_header * p_eth_hdr;
	struct ip * p_ip_hdr;
	struct icmp * p_icmp_hdr;
	char info[100];
	char ip_src[16];
	char ip_dst[16];
	int code;
	
	p_eth_hdr = (struct ether_header *)buffer;
	p_ip_hdr = (struct ip *)(buffer + 14);
	p_icmp_hdr = (struct icmp *)(buffer + 14 + p_ip_hdr->ip_hl * 4);
	
	inet_ntop(AF_INET, &p_ip_hdr->ip_src.s_addr, ip_src, sizeof(ip_src));
	inet_ntop(AF_INET, &p_ip_hdr->ip_dst.s_addr, ip_dst, sizeof(ip_dst));
	
	code = p_icmp_hdr->icmp_type;
	
	if(ICMP_ECHOREPLY_CC == code) {	
		sprintf(info, "Echo reply");	
	} else if(ICMP_ECHO_CC == code) {
		sprintf(info, "Echo request");
	} else {
		sprintf(info, "ICMP Code: %d", code);
	}
	
	add_to_list(
		list, 
		no, 
		(lt_now - lt_start)/1000.0, 
		ip_src, 
		ip_dst, 
		"ICMP", 
		info,
		"#000000",
		"#c2c2ff");
}

// tcp
void proc_tcp(GtkWidget * list, char * buffer, time_t lt_start, time_t lt_now, int no) {
	
	struct ether_header * p_eth_hdr;
	struct ip * p_ip_hdr;
	struct tcphdr * p_tcp_hdr;
	char info[100];
	char ip_src[16];
	char ip_dst[16];
	int set_fd = 0;
	
	p_eth_hdr = (struct ether_header *)buffer;
	p_ip_hdr = (struct ip *)(buffer + 14);
	p_tcp_hdr = (struct tcphdr *)(buffer + 14 + p_ip_hdr->ip_hl * 4);
	
	inet_ntop(AF_INET, &p_ip_hdr->ip_src.s_addr, ip_src, sizeof(ip_src));
	inet_ntop(AF_INET, &p_ip_hdr->ip_dst.s_addr, ip_dst, sizeof(ip_dst));
	
	sprintf(info, "%d > %d ", ntohs(p_tcp_hdr->source), ntohs(p_tcp_hdr->dest));
	
	
	if(0 != p_tcp_hdr->fin)
		if(0 == set_fd) {
			set_fd = 1;
			strcat(info, "[FIN");
		} else strcat(info, ", FIN");
	
	if(0 != p_tcp_hdr->syn)
		if(0 == set_fd) {
			set_fd = 1;
			strcat(info, "[SYN");
		} else strcat(info, ", SYN");
	
	if(0 != p_tcp_hdr->rst)
		if(0 == set_fd) {
			set_fd = 1;
			strcat(info, "[RST");
		} else strcat(info, ", RST");
	
	if(0 != p_tcp_hdr->psh)
		if(0 == set_fd) {
			set_fd = 1;
			strcat(info, "[PUSH");
		} else strcat(info, ", PUSH");
	
	if(0 != p_tcp_hdr->ack)
		if(0 == set_fd) {
			set_fd = 1;
			strcat(info, "[ACK");
		} else strcat(info, ", ACK");
	
	if(0 != p_tcp_hdr->urg)
		if(0 == set_fd) {
			set_fd = 1;
			strcat(info, "[URG");
		} else strcat(info, ", URG");
	
	strcat(info, "]");
	
	add_to_list(
		list, 
		no, 
		(lt_now - lt_start)/1000.0, 
		ip_src, 
		ip_dst, 
		"TCP", 
		info,
		"#000000",
		"#8dff7f");
}

// udp
void proc_udp(GtkWidget * list, char * buffer, time_t lt_start, time_t lt_now, int no) {
	struct ether_header * p_eth_hdr;
	struct ip * p_ip_hdr;
	struct udphdr * p_udp_hdr;
	char info[100];
	char ip_src[16];
	char ip_dst[16];
	
	p_eth_hdr = (struct ether_header *)buffer;
	p_ip_hdr = (struct ip *)(buffer + 14);
	p_udp_hdr = (struct udphdr *)(buffer + 14 + p_ip_hdr->ip_hl * 4);
	
	inet_ntop(AF_INET, &p_ip_hdr->ip_src.s_addr, ip_src, sizeof(ip_src));
	inet_ntop(AF_INET, &p_ip_hdr->ip_dst.s_addr, ip_dst, sizeof(ip_dst));
	
	sprintf(info, "Source port: %d, Destination port: %d ", ntohs(p_udp_hdr->source), ntohs(p_udp_hdr->dest));
	
	add_to_list(
		list, 
		no, 
		(lt_now - lt_start)/1000.0, 
		ip_src, 
		ip_dst, 
		"UDP", 
		info,
		"#000000",
		"#70e0ff");
}

// http
void proc_http(GtkWidget * list, char * buffer, time_t lt_start, time_t lt_now, int no) {
	
	struct ether_header * p_eth_hdr;
	struct ip * p_ip_hdr;
	struct tcphdr * p_tcp_hdr;
	char info[64];
	char ip_src[16];
	char ip_dst[16];
	int p;
	int i=0;
	
	p_eth_hdr = (struct ether_header *)buffer;
	p_ip_hdr = (struct ip *)(buffer + 14);
	p_tcp_hdr = (struct tcphdr *)(buffer + 14 + p_ip_hdr->ip_hl * 4);
	
	inet_ntop(AF_INET, &p_ip_hdr->ip_src.s_addr, ip_src, sizeof(ip_src));
	inet_ntop(AF_INET, &p_ip_hdr->ip_dst.s_addr, ip_dst, sizeof(ip_dst));
	
	p = 14 + p_ip_hdr->ip_hl * 4 + p_tcp_hdr->doff * 4;
	
	
	if(0 == str_cmp_cc(buffer + p, "GET", 3, FALSE)) {
		while('\r' != buffer[p] && '\n' != buffer[p+1] && i < 63) {
			info[i] = buffer[p];
			i++;
			p++;
		}
		info[i] = '\0';
	} else {
		sprintf(info, "Continuation or non-HTTP traffic");
	}	
	
	add_to_list(
		list, 
		no, 
		(lt_now - lt_start)/1000.0, 
		ip_src, 
		ip_dst, 
		"HTTP", 
		info,
		"#000000",
		"#fffa99");
	
}

void proc_thread(gpointer arg, gpointer user_data) {

	struct t_arg * parg = (struct t_arg *)arg;
	GtkWidget * tv = parg->tv;
	time_t lt_start = parg->lt_start;
	time_t lt_now = parg->lt_now;
	int * no = parg->no;
	FILE * fp_index = parg->fp_index;
	FILE * fp_data = parg->fp_data;
	char * buf = parg->buf;
	int n_read = parg->data_len;
	long * data_index = parg->data_index;
	
	int i;
	long index_fp, data_fp, total_len;
	
	struct _hash {
		int proto_type;
		void (*proc)(GtkWidget * list, char * buf, time_t lt_start, time_t lt_now, int no);
	} hash[] = {
		PROTO_ARP,	proc_arp,
		PROTO_ICMP,	proc_icmp,
		PROTO_TCP,	proc_tcp,
		PROTO_UDP,	proc_udp,
		PROTO_HTTP,	proc_http
	};
	
	int pt = get_proto_type(buf);
	
	for(i=0; i<sizeof(hash); i++) {
		
		if(hash[i].proto_type != pt)
			continue;

		pthread_mutex_lock(&mutex);	

		(*no)++;	
		if(1 == ((*no) % FILE_INCREMENT)) {
			index_fp = ftell(fp_index);
			data_fp = ftell(fp_data);
			fseek(fp_data, 0, SEEK_END);
			total_len = ftell(fp_data);
					
			fwrite("\0", 1, (sizeof(int) + sizeof(long) + sizeof(time_t)) * FILE_INCREMENT, fp_index);
			fwrite("\0", 1, (BUF_SZ * FILE_INCREMENT - total_len + data_fp), fp_data);
			fseek(fp_index, index_fp, SEEK_SET);
			fseek(fp_data, data_fp, SEEK_SET);
		}

		fwrite(&(*data_index), sizeof(long), 1, fp_index);
		fwrite(&n_read, sizeof(int), 1, fp_index);
		fwrite(&lt_now, sizeof(time_t), 1, fp_index);
		fflush(fp_index);
				
		fwrite(buf, n_read, 1, fp_data);
		fflush(fp_data);
		
		(*hash[i].proc)(tv, buf, lt_start, lt_now, (*no)-1);
				
		(*data_index) += n_read;
		pthread_mutex_unlock(&mutex);
		free(arg);
		free(buf);
		break;
			
	} //for(i=0; i<sizeof(hash); i++) {
	
	return;
}

void * sniffer(void * l) {
	GtkWidget * list = (GtkWidget *)l;
	int sockfd,
		n_read,
		proto,
		no = 1,
		i;
		
	long index_fp, data_fp, total_len; //file cursor position
		
	FILE * fp_index,
		 * fp_data;
	
	time_t lt_start, lt_now;
	long data_index = 0;
	
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) error");
		return NULL;
	}
	
	if((fp_index = fopen("capture_index.dat", "wb")) == NULL) {
		perror("can't open capture_index.dat");
		return NULL;
	}
	
	if((fp_data = fopen("capture_data.dat", "wb")) == NULL) {
		perror("can't open capture_data.dat");
		return NULL;
	}
	
	fwrite("\0", 1, (sizeof(int) + sizeof(long) + sizeof(time_t)) * FILE_INCREMENT, fp_index);
	fwrite("\0", 1, BUF_SZ * FILE_INCREMENT, fp_data);
	fseek(fp_index, 0, SEEK_SET);
	fseek(fp_data, 0, SEEK_SET);

	/* time the capture start */
	lt_start = time(NULL);
	g_object_set_data_full(G_OBJECT(list), "time_start", (gpointer)lt_start, NULL);
	
	/* recv loop */
	GThreadPool * tpool = g_thread_pool_new(proc_thread, NULL, MAX_THREADS, FALSE, NULL);
	
	while((gboolean)g_object_get_data(G_OBJECT(list), "flag")) {
		char * buf;
		buf = (char *)malloc(BUF_SZ);
		
		if(NULL == buf) {
			g_printf("malloc failed.\n");
			continue;
		}
		
		n_read = recvfrom(sockfd, buf, BUFFER_MAX, 0, NULL, NULL);
		
		if(n_read < 42) {
			free(buf);
			continue;
		}
		
		struct t_arg * arg = (struct t_arg *)malloc(sizeof(struct t_arg));
		
		lt_now = time(NULL);		
		
		arg->tv = list;
		arg->lt_start = lt_start;
		arg->lt_now = lt_now;
		arg->no = &no;
		arg->fp_index = fp_index;
		arg->fp_data = fp_data;
		arg->buf = buf;
		arg->data_len = n_read;
		arg->data_index = &data_index;
			
		g_thread_pool_push(tpool, arg, NULL);
	} //while((gboolean)g_object_get_data(G_OBJECT(list), "flag")) {
	
	g_object_set_data_full(G_OBJECT(list), "flag", (gpointer)TRUE, NULL);
	while(g_thread_pool_get_num_threads(tpool)) {
		usleep(100000);
	}
	fclose(fp_index);
	fclose(fp_data);
}

