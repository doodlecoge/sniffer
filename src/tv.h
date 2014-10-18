#ifndef TREEVIEW_H
#define TREEVIEW_H

#include <gtk/gtk.h>
#include "support.h"

#include<string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
//#include <linux/in.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/if_ether.h>
#include<arpa/inet.h>
#include<net/ethernet.h>

#include"constants.h"
#include "dbg.h"



enum
{
  LIST_NO = 0,
  LIST_TIME,
  LIST_SRC,
  LIST_DST,
  LIST_PROTO,
  LIST_INFO,
  LIST_COLOR,
  LIST_BG,
  //LIST_SET,
  N_COLUMNS
};

void sh_mem_in_ascii(void * buf, int len) {
	char * m = (char *)buf;
	int i=0;
	for(; i<len; i++) {
		if(
			'0' <= m[i] && 
			'9' >= m[i] || 
			'a' <= m[i] && 
			'z' >= m[i] || 
			'A' <= m[i] && 
			'Z' >= m[i]) {
			printf("%c", m[i]);
		} else {
			printf(".");
		}
	}
	
}


int sh_mem_in_hex_fmt(void * mem, const int len) {
	int i;
	u_int8_t * m = (u_int8_t *)mem;
	for(i=0; i<len; i++) {
		if(0 != i && 0 == i % 16)
			printf("\n");
		printf("%02x", m[i]);
		if(len != i + 1)
			printf(":");
	}
	
	printf("\n");	
	return 0;
}


void get_eth_type_str(int type, char * type_str) {
	switch(type) {
		case ETHERTYPE_IP:
			sprintf(type_str, "%s", "IP");
			break;
		
		case ETHERTYPE_ARP:
			sprintf(type_str, "%s", "ARP");
			break;
			
		default:
			sprintf(type_str, "%s", "");
	}
}

void get_ip_p(u_int8_t type, char * type_str) {
	switch(type) {
		case IPPROTO_ICMP:
		sprintf(type_str, "%s", "ICMP");
		break;
		
		case IPPROTO_TCP:
		sprintf(type_str, "%s", "TCP");
		break;
		
		case IPPROTO_UDP:
		sprintf(type_str, "%s", "UDP");
		break;
		
		default:
			sprintf(type_str, "%s", "");
	}
}



gchar int_to_hex_chr(int n) {
	char hex[] = "0123456789abcdef";
	return hex[n%16];
}

void int8_to_02x(void * buf, u_int8_t num) {
	gchar * b = (gchar *)buf;
	b[0] = int_to_hex_chr(num/16);
	b[1] = int_to_hex_chr(num%16);
}

void index_(void * buf, int i) {
	gchar * b = (gchar *)buf;
	i/=16;
	b[3] = int_to_hex_chr(i%16);
	i/=16;
	
	b[2] = int_to_hex_chr(i%16);
	i/=16;
	
	b[1] = int_to_hex_chr(i%16);
	i/=16;
	
	b[0] = int_to_hex_chr(i);
	b[4] = ' ';
	b[5] = ' ';
}

void show_binary(GtkWidget * txt, char * buf, int len) {
	
	char b[BUF_SZ * 3];
	memset(b, ' ', BUF_SZ * 3);
	int i;	
	int w = 74;
	for(i=0; i<len; i++) {
		if(0 == (i%16)) {
			index_(b+i/16*w, i/16*16);
			b[i/16*w+w-1] = '\n';
		}
		if(i%16 < 8) {
			int8_to_02x(b+i/16*w+(i%16)*3 + 6, buf[i]);
			if(32 <= buf[i] && 126 >= buf[i])
				b[i/16*w+(i%16) + 56] = buf[i];
			else
				b[i/16*w+(i%16) + 56] = '.';
		} else {
			int8_to_02x(b+i/16*w+(i%16)*3 + 7, buf[i]);
			if(32 <= buf[i] && 126 >= buf[i])
				b[i/16*w+(i%16) + 57] = buf[i];
			else
				b[i/16*w+(i%16) + 57] = '.';
		}
	}
		
	
	b[len/16*w+w] = 0;
	
	gtk_text_buffer_set_text (gtk_text_view_get_buffer (GTK_TEXT_VIEW (txt)), _(b), -1);
}


void apply_tag(GtkWidget * textview, GtkTextBuffer *buffer, int start, int end) {

	int sln, eln, ts, te, tln, i, w = 74;
	GtkTextIter mstart, mend;
	GtkTextMark *last_pos;
			
	sln = start / 16;
	eln = end /16;
	tln = eln - sln + 1;
			
	if(sln == eln) {
			
		/* hex */
		ts = 
		start / 16 * w + 
		start % 16 * 3 + 
		6 + (((start % 16) >= 8) ? 1 : 0);
					
		te = 
			end / 16 * w + 
			end % 16 * 3 + 
			8 + (((end % 16) >= 8) ? 1 : 0);
				
		gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
		gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
		gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
				
		/* ascii */
		ts = 
			start / 16 * w + 
			start % 16 + 
			56 + (((start % 16) >= 8) ? 1 : 0);
					
		te = 
			end / 16 * w + 
			end % 16 + 
			57 + (((end % 16) >= 8) ? 1 : 0);
				
		gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
		gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
		gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
				
	} else {
			
		/* hex */
		ts = 
			start / 16 * w + 
			start % 16 * 3 + 
			6 + (((start % 16) >= 8) ? 1 : 0);
					
		te = start / 16 * w + 54;
				
		gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
		gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
		gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
				
		/* ascii */
		ts = 
			start / 16 * w + 
			start % 16 + 
			56 + (((start % 16) >= 8) ? 1 : 0);
					
		te = start / 16 * w + 73;
				
		gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
		gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
		gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
				
		for(i=sln+1; i< eln; i++) {
				
			/* hex */
			ts = 6 + i * w;
			te = 54 + i * w;
					
			gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
			gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
			gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
					
			/* ascii */
			ts = 56 + i * w;
			te = 73 + i * w;
					
			gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
			gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
			gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
					
		}
				
		/* hex */
		ts = 6 + i * w;
		te = 
			end / 16 * w + 
			end % 16 * 3 + 
			8 + (((end % 16) >= 8) ? 1 : 0);
					
		gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
		gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
		gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
				
		/* ascii */
		ts = 56 + i * w;
		te = 
			end / 16 * w + 
			end % 16 + 
			57 + (((end % 16) >= 8) ? 1 : 0);
					
		gtk_text_buffer_get_iter_at_offset(buffer, &mstart, ts);
		gtk_text_buffer_get_iter_at_offset(buffer, &mend, te);
		gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
				
	}
			
	gtk_text_buffer_apply_tag_by_name (buffer, "tag", &mstart, &mend);
	gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(textview), &mstart, 0, TRUE, 0, 0);
}


gboolean view_hex(
	GtkTreeSelection *selection,
	GtkTreeModel * model,
	GtkTreePath * path,
	gboolean path_currently_selected,
	gpointer userdata
	) {
	
	//printf("view hex\n");
	GtkTreeIter iter;
	GtkTextIter mstart, mend;
	GtkTextBuffer *buffer;
	GtkWidget * textview; 
	
    if (gtk_tree_model_get_iter(model, &iter, path)) {
		
		if(!path_currently_selected) {
			
			textview = lookup_widget(GTK_WIDGET(userdata), "textview");
			buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview));
			gtk_text_buffer_get_bounds(buffer, &mstart, &mend);
			gtk_text_buffer_remove_all_tags (buffer, &mstart, &mend);
			
			
			int start, end;
		  	gtk_tree_model_get(model, &iter, 1, &start, 2, &end, -1);
		  	//g_print("start: %d, end: %d\n", start, end);
		  	
		  	if(start > end || start < 0 || end < 0)
		  		return TRUE;
		  		
		  	if(0 == start && 0 == end) {
		  		return TRUE;
		  	}
			
			apply_tag(textview, buffer, start, end);

      	}
      	
    }

    return TRUE; /* allow selection state to change */
}

/* show detail */
void show_detail(GtkWidget * view, gchar * buffer, int no, int len, time_t t_cap) {
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkTreeStore * treestore;
	GtkTreeIter toplevel, child, t;
	char info[100];
	char _type[10];
	char mac_src[18];
	char mac_dst[18];
	char ip_src[16];
	char ip_dst[16];  
	struct ether_header * p_eth_hdr;
	struct arphdr * p_arp_hdr;
	struct ip * p_ip_hdr;
	struct tcphdr * p_tcp_hdr;
	struct udphdr * p_udp_hdr;
	struct icmp * p_icmp_hdr;
	struct ether_arp * p_eth_arp;
	GtkTreeSelection *selection; 	
	int s, e, hp;

	treestore = GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW (view)));
	if(treestore != NULL){
		gtk_tree_store_clear(treestore);
	} else {
		gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(view), FALSE);
		col = gtk_tree_view_column_new();
		gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
		renderer = gtk_cell_renderer_text_new();
		g_object_set(renderer, "cell-background", "#eeeeee", "cell-background-set", TRUE, "ypad", 0, NULL); 
		gtk_tree_view_column_pack_start(col, renderer, TRUE);
		gtk_tree_view_column_add_attribute(col, renderer, "text", 0);
	}
	
	
  	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));
  	gtk_tree_selection_set_select_function(selection, view_hex, view, NULL);

	s = e = 0;

  	treestore = gtk_tree_store_new(3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT);
  	
  	/* frame info */
  	gtk_tree_store_append(treestore, &toplevel, NULL);  	
  	sprintf(info, "Frame %d (%d bytes captured)", no, len);
  	gtk_tree_store_set(treestore, &toplevel, 0, info, 1, 0, 2, len - 1, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	time(&t_cap);
	sprintf(info, "Arrival Time: %s", ctime(&t_cap));
	info[strlen(info) - 1] = 0;
	gtk_tree_store_set(treestore, &child, 0, info,  1, 0, 2, 0,-1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	sprintf(info, "Frame Number: %d", no);
	gtk_tree_store_set(treestore, &child, 0, info, 1, 0, 2, 0, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	sprintf(info, "Frame Length: %d", len);
	gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	sprintf(info, "Capture Length: %d", len);
	gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	sprintf(info, "Protocols in frame: %s", " ");
	gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	GtkWidget * list = lookup_widget(GTK_WIDGET(view), "treeview_2nd");
	long t_start = (long)g_object_get_data(G_OBJECT(list), "time_start");
	sprintf(info, "Time since first frame: %f", (t_cap - t_start)/1000.0);
	gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
	
	/* ether info */
	p_eth_hdr = (struct ether_header *)(buffer);
	ether_ntoa_r(p_eth_hdr->ether_shost, mac_src);
	ether_ntoa_r(p_eth_hdr->ether_dhost, mac_dst);
		
	sprintf(info, "Ethernet II, Src: %s, Dst: %s", mac_src, mac_dst);
	gtk_tree_store_append(treestore, &toplevel, NULL);
	gtk_tree_store_set(treestore, &toplevel, 0, info, 1, 0, 2, 13, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	sprintf(info, "Destination: %s", mac_dst);
	gtk_tree_store_set(treestore, &child, 0, info, 1, 0, 2, 5, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	sprintf(info, "Source: %s", mac_src);
	gtk_tree_store_set(treestore, &child, 0, info, 1, 6, 2, 11, -1);
	
	gtk_tree_store_append(treestore, &child, &toplevel);
	get_eth_type_str(ntohs(p_eth_hdr->ether_type), _type);
	sprintf(info, "Type: %s", _type);
	gtk_tree_store_set(treestore, &child, 0, info, 1, 12, 2, 13, -1);
		
	/* ip */
	if(ETHERTYPE_IP == ntohs(p_eth_hdr->ether_type)) {
			
		p_ip_hdr = (struct ip *)(buffer + 14);
		hp = 14;
		inet_ntop(AF_INET, &p_ip_hdr->ip_src.s_addr, ip_src, sizeof(ip_src));
		inet_ntop(AF_INET, &p_ip_hdr->ip_dst.s_addr, ip_dst, sizeof(ip_dst));
			
		sprintf(info, "Internet Protocol, Src: %s, Dst: %s", ip_src, ip_dst);
		gtk_tree_store_append(treestore, &toplevel, NULL);
		s = hp, e = s + p_ip_hdr->ip_hl * 4 - 1;
		gtk_tree_store_set(treestore, &toplevel, 0, info, 1, s, 2, e, -1);
		
		/* ip version */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Version: %d", p_ip_hdr->ip_v);
		s = hp; e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* header length */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Header Length: %d", p_ip_hdr->ip_hl * 4);
		s = hp, e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);

		/* tos */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Differentiated Service Field: %s", "");
		s = hp+1, e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* total length */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Total Length: %d", ntohs(p_ip_hdr->ip_len));
		s = hp+2, e = s+1;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* identification */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Identification: 0x%04x (%d)", p_ip_hdr->ip_id, p_ip_hdr->ip_id);
		s = hp+4, e = s+1;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* flag */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Flags: 0x%02x", p_ip_hdr->ip_off & 0xe000);
		s = hp+6, e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);

		gtk_tree_store_append(treestore, &t, &child);
		sprintf(info, "%d... = Reserved bit: %s", 
			((p_ip_hdr->ip_off & IP_RF) == 0) ? 0 : 1, 
			((p_ip_hdr->ip_off & IP_RF) == 0) ? "Not set" : "Set");
		s = hp+6, e = s+0;
		gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &t, &child);
		sprintf(info, ".%d.. = Don't fragment: %s", 
			((p_ip_hdr->ip_off & IP_DF) == 0) ? 0 : 1, 
			((p_ip_hdr->ip_off & IP_DF) == 0) ? "Not set" : "Set");
		s = hp+6, e = s+0;
		gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &t, &child);
		sprintf(info, "..%d. = More fragment: %s", 
			((p_ip_hdr->ip_off & IP_MF) == 0) ? 0 : 1, 
			((p_ip_hdr->ip_off & IP_MF) == 0) ? "Not set" : "Set");
		s = hp+6, e = s+0;
		gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
	
		/* fragment offset */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Fragment offset: %d", p_ip_hdr->ip_off & IP_OFFMASK);
		s = hp+6, e = s+1;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* time to live */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Time ot live: %d", p_ip_hdr->ip_ttl);
		s = hp+8, e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* Protocol */
		gtk_tree_store_append(treestore, &child, &toplevel);
		get_ip_p(p_ip_hdr->ip_p, _type);
		sprintf(info, "Protocol: %s (0x%02x)", _type, p_ip_hdr->ip_p);
		s = hp+9, e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* check sum */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Header checksum: 0x%04x", p_ip_hdr->ip_sum);
		s = hp+10, e = s+1;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* source */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Source: %s", ip_src);
		s = hp+12, e = s+3;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		/* destination */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Destination: %s", ip_dst);
		s = hp+16, e = s+3;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
	
		/* icmp */
		if(IPPROTO_ICMP == p_ip_hdr->ip_p) {
		
			p_icmp_hdr = (struct icmp *)(buffer + 14 + p_ip_hdr->ip_hl * 4);
			gtk_tree_store_append(treestore, &toplevel, NULL);
			hp = (u_int8_t *)p_icmp_hdr - (u_int8_t *)buffer;
			s = hp, e = s+ntohs(p_ip_hdr->ip_len)-p_ip_hdr->ip_hl*4-1;
			gtk_tree_store_set(treestore, &toplevel, 0, "Internet Control Message protocol", 1, s, 2, e, -1);
			
			hp = (u_int8_t *)p_icmp_hdr - (u_int8_t *)buffer;
			
			/* type */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Type: %d", p_icmp_hdr->icmp_type);
			s = hp, e = s+0;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* code */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Code: %d", p_icmp_hdr->icmp_code);
			s = hp+1, e = s+0;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* icmp checksum */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Checksum: 0x%04x", p_icmp_hdr->icmp_cksum);
			s = hp+2, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* other */
				
		}
		/* tcp */
		else if(IPPROTO_TCP == p_ip_hdr->ip_p) {
		
			p_tcp_hdr = (struct tcphdr *)(buffer + 14 + p_ip_hdr->ip_hl * 4);
			sprintf(info, "Transmission Control Protocol, Src Port: %d, Dst port: %d", 
				ntohs(p_tcp_hdr->source), ntohs(p_tcp_hdr->dest));
			gtk_tree_store_append(treestore, &toplevel, NULL);
			hp = (u_int8_t *)p_tcp_hdr - (u_int8_t *)buffer;
			s = hp, e = s + p_tcp_hdr->doff * 4 - 1;
			gtk_tree_store_set(treestore, &toplevel, 0, info, 1, s, 2, e, -1);	
			
			/* source port*/
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Source port: %d", ntohs(p_tcp_hdr->source));
			s = hp, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);		
			
			/* destination port */	
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Destination port: %d", ntohs(p_tcp_hdr->dest));
			s = hp+2, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* sequence number */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Sequence number: %lu", ntohl(p_tcp_hdr->seq));
			s = hp+4, e = s+3;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* Acknowledgement number */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Acknowledgement number: %lu", ntohl(p_tcp_hdr->ack_seq));
			s = hp+8, e = s+3;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* header length */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Header length: %d", p_tcp_hdr->doff * 4);
			s = hp+12, e = s+0;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* flags */
			gtk_tree_store_append(treestore, &child, &toplevel);
			u_int8_t flags = 0;
			flags = 
				(p_tcp_hdr->res2 << 6) + 
				(p_tcp_hdr->urg << 5) +
				(p_tcp_hdr->ack << 4) +
				(p_tcp_hdr->psh << 3) +
				(p_tcp_hdr->rst << 2) +
				(p_tcp_hdr->syn << 1) +
				p_tcp_hdr->fin;
			//printf("flags: %d\n", flags);
			sprintf(info, "Flags: 0x%02x", flags);
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, "%d... .... = Congestion Window Reduced (CWR): %s", 
				((p_tcp_hdr->res2 & 0x02) == 0) ? 0 : 1, 
				((p_tcp_hdr->res2 & 0x02) == 0) ? "Not set" : "Set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, ".%d.. .... = ECN-Echo: %s", 
				((p_tcp_hdr->res2 & 0x01) == 0) ? 0 : 1, 
				((p_tcp_hdr->res2 & 0x01) == 0) ? "Not set" : "Set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, "..%d. .... = Urgent: %s", 
				p_tcp_hdr->urg, p_tcp_hdr->urg ? "Set" : "Not set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, "...%d .... = Acknowledgement: %s", 
				p_tcp_hdr->ack, p_tcp_hdr->ack ? "Set" : "Not set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, ".... %d... = Push: %s", 
				p_tcp_hdr->psh, p_tcp_hdr->psh ? "Set" : "Not set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, ".... .%d.. = Reset: %s", 
				p_tcp_hdr->rst, p_tcp_hdr->rst ? "Set" : "Not set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, ".... ..%d. = Syn: %s", 
				p_tcp_hdr->syn, p_tcp_hdr->syn ? "Set" : "Not set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			gtk_tree_store_append(treestore, &t, &child);
			sprintf(info, ".... ...%d = Fin: %s", 
				p_tcp_hdr->fin, p_tcp_hdr->fin ? "Set" : "Not set");
			s = hp+13, e = s+0;
			gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
			
			/* window size */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Window size: %d", p_tcp_hdr->window);
			s = hp+14, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* checksum */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Checksum: 0x%04x", p_tcp_hdr->check);
			s = hp+16, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* options if have */
			if((p_tcp_hdr->doff * 4) > 20) {
			
				gtk_tree_store_append(treestore, &child, &toplevel);
				int idx;
				for(idx=0; idx<(p_tcp_hdr->doff * 4 - 20);) {
					if(((u_int8_t *)p_tcp_hdr)[20 + idx] == 0) {
						break;
					} else if(((u_int8_t *)p_tcp_hdr)[20 + idx] == 1) {
						idx++;
					} else {
						idx += ((u_int8_t *)p_tcp_hdr)[20 + idx + 1];
					}
				}
				sprintf(info, "Options: (%d bytes)", idx);
				s = hp+20, e = s+idx-1;
				gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
				
				for(idx=0; idx<(p_tcp_hdr->doff * 4 - 20);) {
					if(((u_int8_t *)p_tcp_hdr)[20 + idx] == 0) {
					
						break;
						
					} else if(((u_int8_t *)p_tcp_hdr)[20 + idx] == 1) {
					
						gtk_tree_store_append(treestore, &t, &child);
						s = hp+20+idx, e = s+0;
						gtk_tree_store_set(treestore, &t, 0, "NOP", 1, s, 2, e, -1);
						idx++;
						
					} else {
						u_int8_t * p = (u_int8_t *)(buffer + 14 + p_ip_hdr->ip_hl * 4 + 20);
						//MSS
						if(2 == ((u_int8_t *)p_tcp_hdr)[20 + idx]) {
						
							gtk_tree_store_append(treestore, &t, &child);
							u_int16_t * pmss = (u_int16_t *)(p + idx +2);
							sprintf(info, "Maximum segment size: %d", ntohs(*pmss));
							s = hp+20+idx, e = s+((u_int8_t *)p_tcp_hdr)[20 + idx + 1]-1;
							gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
							
						} else if(3 == ((u_int8_t *)p_tcp_hdr)[20 + idx]) {
							
							gtk_tree_store_append(treestore, &t, &child);
							sprintf(info, "Window scale: %d", ((u_int8_t *)(p + idx + 2))[0]);
							s = hp+20+idx, e = s+((u_int8_t *)p_tcp_hdr)[20 + idx + 1]-1;
							gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
						
						} else if(8 == ((u_int8_t *)p_tcp_hdr)[20 + idx]) {
						
							gtk_tree_store_append(treestore, &t, &child);
							time_t *ts_val, *ts_ecr;
							ts_val = (time_t *)(p + idx + 2);
							ts_ecr = (time_t *)(p + idx + 6);
							sprintf(info, "Timestamps: TSval %ld, TSecr %ld", ntohl(*ts_val), ntohl(*ts_ecr));
							s = hp+20+idx, e = s+((u_int8_t *)p_tcp_hdr)[20 + idx + 1]-1;
							gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
							
						}
						idx += ((u_int8_t *)p_tcp_hdr)[20 + idx + 1];
						
					}
				} // for(idx=0; idx<(p_tcp_hdr->doff * 4 - 20);) {
				
			} // if((p_tcp_hdr->doff * 4) > 20) {
			
			int i, p, len;
			if((ntohs(p_ip_hdr->ip_len) - p_ip_hdr->ip_hl * 4 - p_tcp_hdr->doff * 4) > 0) {
				p = (u_int8_t *)p_tcp_hdr - (u_int8_t *)buffer + p_tcp_hdr->doff * 4;
				len = ntohs(p_ip_hdr->ip_len) - p_ip_hdr->ip_hl * 4 - p_tcp_hdr->doff * 4;
				
				/*
				if(-1 == str_idx((char *)(buffer+p), "\r\n", len, 2, FALSE)) {
				
					gtk_tree_store_append(treestore, &child, &toplevel);
					sprintf(info, "TCP data (%d bytes)", len);
					s = p, e = s+len;
					gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
					
				} else {
					
				}*/
				
				//printf(">>%d\n", str_cmp_cc(buffer+p, "GET", 3, FALSE));
				if((0 == str_cmp_cc(buffer+p, "GET", 3, FALSE)) || (0 == str_cmp_cc(buffer+p, "POST", 4, FALSE))) {
					
					gtk_tree_store_append(treestore, &toplevel, NULL);
					s = p, e = s+len-1;
					gtk_tree_store_set(treestore, &toplevel, 0, "Hypertext Transfer Protocol", 1, s, 2, e, -1);

					gtk_tree_store_append(treestore, &child, &toplevel);
					int bz = 128;
					int n_get;
					char * ln = (char *)malloc(bz + 5);
					while(-1 == (n_get = get_line_cc(ln, buffer + p, bz))) {
						bz += 128;
						free(ln);
						ln = (char *)malloc(bz + 5);
					}
					
					ln[n_get-1] = '\\';
					ln[n_get] = 'r';
					ln[n_get+1] = '\\';
					ln[n_get+2] = 'n';
					ln[n_get+3] = '\0';				

					s = p, e = s+n_get;
					gtk_tree_store_set(treestore, &child, 0, ln, 1, s, 2, e, -1);
					
					
					if(0 == str_cmp_cc(buffer+p, "GET", 3, FALSE)) {
						
						//request method
						gtk_tree_store_append(treestore, &t, &child);
						s = p, e = s+2;
						gtk_tree_store_set(treestore, &t, 0, "Request Method: GET", 1, s, 2, e, -1);
						
						//uri
						gtk_tree_store_append(treestore, &t, &child);
						char * tok;
						char * del = " ";
						tok = strtok(ln, del);
						tok = strtok(NULL, del);
						memset(info, 0, strlen(info));
						strcat(info, "Request URI: ");
						strcat(info, tok);
						s = p+4, e = s+strlen(tok)-1;
						gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
						
						//version
						tok = strtok(NULL, del);
						memset(info, 0, strlen(info));
						strcat(info, "Request Version: ");
						strcat(info, tok);
						info[strlen(info)-4] = 0;
						s = e+2; e = s+strlen(tok)-1-2;
						gtk_tree_store_append(treestore, &t, &child);
						gtk_tree_store_set(treestore, &t, 0, info, 1, s, 2, e, -1);
						
					} else if(0 == str_cmp_cc(buffer+p, "POST", 4, FALSE)) {
						printf("POST\n");
					}	
					
					free(ln);
					
					ln = (char *)malloc(len - n_get - 1 + 8);
					memset(ln, 0, len - n_get - 1 + 8);
					memcpy(ln, buffer+p+1+n_get, len - n_get - 1);
					char * tok;
					tok = strtok(ln, "\r\n");
					if(NULL != tok) {
						gtk_tree_store_append(treestore, &child, &toplevel);
						memset(info, 0, strlen(info));
						str_cat_cc(info, tok, 64);
						strcat(info, "\\r\\n");
						s = p+n_get+1, e = s+strlen(tok)-1+2;
						gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
					}
					
					
					int frame_end_p = (u_int8_t *)p_ip_hdr - (u_int8_t *)buffer + ntohs(p_ip_hdr->ip_len);
					while((tok = strtok(NULL, "\r\n"))) {						
						
						memset(info, 0, strlen(info));
						str_cat_cc(info, tok, 64);
						s = e+1;
						e = s+strlen(tok)-1+2;
						
						if(e > (frame_end_p+2)) { 
							printf("frame: %d, s: %d, e: %d, end: %d, len: %d\n", no, s, e, frame_end_p, strlen(tok)); 
							break;
						}
						
						if(buffer[e-1] != '\r' || buffer[e] != '\n') {
							printf("fragment\n"); 
							e -= 2;
						} else strcat(info, "\\r\\n");
						
						gtk_tree_store_append(treestore, &child, &toplevel);
						gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
						
					}
					
					free(ln);
					
					if(
						('\r' == buffer[frame_end_p-4]) &&
						('\n' == buffer[frame_end_p-3]) &&
						('\r' == buffer[frame_end_p-2]) &&
						('\n' == buffer[frame_end_p-1])) {
							gtk_tree_store_append(treestore, &child, &toplevel);
							s = frame_end_p-2; e = s+1;
							gtk_tree_store_set(treestore, &child, 0, "\\r\\n", 1, s, 2, e, -1);
					}
					
				}
				
			}//if((ntohs(p_ip_hdr->ip_len) - p_ip_hdr->ip_hl * 4 - p_tcp_hdr->doff * 4) > 0) {
		}
		/* udp */
		else if(IPPROTO_UDP == p_ip_hdr->ip_p) {
		
			p_udp_hdr = (struct udphdr *)(buffer + 14 + p_ip_hdr->ip_hl * 4);
			
			sprintf(info, "User Datagrame Protocol, Src Port: %d, Dst port: %d", 
				ntohs(p_udp_hdr->source), ntohs(p_udp_hdr->dest));
			gtk_tree_store_append(treestore, &toplevel, NULL);
			hp = (u_int8_t *)p_udp_hdr - (u_int8_t *)buffer;
			s = hp, e = s+7;
			gtk_tree_store_set(treestore, &toplevel, 0, info, 1, s, 2, e, -1);
			
			/* source port */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Source port: %d", ntohs(p_udp_hdr->source));
			s = hp, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* destination port */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Destination port: %d", ntohs(p_udp_hdr->dest));
			s = hp+2, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* length */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Length: %d", ntohs(p_udp_hdr->len));
			s = hp+4, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* checksum */
			gtk_tree_store_append(treestore, &child, &toplevel);
			sprintf(info, "Checksum: 0x%04x", ntohs(p_udp_hdr->check));
			s = hp+6, e = s+1;
			gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
			
			/* if has data */
			if(8 != ntohs(p_udp_hdr->len)) {
			
				sprintf(info, "Data: %d bytes", ntohs(p_udp_hdr->len) - 8);
				gtk_tree_store_append(treestore, &toplevel, NULL);
				s = hp+8, e = s+ntohs(p_udp_hdr->len)-1-8;
				gtk_tree_store_set(treestore, &toplevel, 0, info, 1, s, 2, e, -1);
				
				gtk_tree_store_append(treestore, &child, &toplevel);
				char hex[] = "0123456789abcdef";
				u_int8_t * p = ((u_int8_t *)p_udp_hdr) + 8;
				int idx;
				sprintf(info, "Data: ");				
				
				for(idx=0; idx < ntohs(p_udp_hdr->len)-8; idx++) {
					if(idx == 24) {
						info[54] = info[55] = info[56] = '.';
						info[57] = 0;
						 break;
					}
					info[idx*2+6] = hex[p[idx] / 16];
					info[idx*2+7] = hex[p[idx] % 16];
				}
				if(24 > idx)
					info[ntohs(p_udp_hdr->len)] = 0;
				
				gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
				
			}
			
			
		} 
		/* other ip based protocol */
		else ;
			
	}
	/* arp */
	else if(ETHERTYPE_ARP == ntohs(p_eth_hdr->ether_type)) {
			
		gtk_tree_store_append(treestore, &toplevel, NULL);
		p_eth_arp = (struct ether_arp *)(buffer + 14);
		hp = 14;//hp = (u_int8_t *)p_eth_arp - (u_int8_t *)buffer;
		s = hp, e = hp + sizeof(struct ether_arp) - 1;
		gtk_tree_store_set(treestore, &toplevel, 0, "Address Resolution Protocol", 1, s, 2, e, -1);

		inet_ntop(AF_INET, p_eth_arp->arp_spa, ip_src, sizeof(ip_src));
		inet_ntop(AF_INET, p_eth_arp->arp_tpa, ip_dst, sizeof(ip_dst));
		//sprintf(info, "Who has %s? Tell %s", ip_dst, ip_src);
		
		/* hardware type */
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Hardware type: 0x%04x", ntohs(p_eth_arp->ea_hdr.ar_hrd));
		s = hp, e = s+1;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Protocol type: 0x%04x", ntohs(p_eth_arp->ea_hdr.ar_pro));
		s = hp+2, e = s+1;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Hardware size: %d", (p_eth_arp->ea_hdr.ar_hln));
		s = hp+4, e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Protocol size: %d", (p_eth_arp->ea_hdr.ar_pln));
		s = hp+5, e = s+0;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Opcode: 0x%04x", ntohs(p_eth_arp->ea_hdr.ar_op));
		s = hp+6, e = s+1;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Sender MAC address: %s", mac_src);
		s = hp+8, e = s+5;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Sender IP address: %s", ip_src);
		s = hp+14, e = s+3;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Target MAC address: %s", mac_dst);
		s = hp+18, e = s+5;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
		gtk_tree_store_append(treestore, &child, &toplevel);
		sprintf(info, "Target IP address: %s", ip_dst);
		s = hp+24, e = s+3;
		gtk_tree_store_set(treestore, &child, 0, info, 1, s, 2, e, -1);
		
	}
	/* other protocol(s) */
	else ;

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), GTK_TREE_MODEL(treestore));
	g_object_unref(treestore); 
}

gboolean
view_selection_func (
	GtkTreeSelection *selection,
	GtkTreeModel * model,
	GtkTreePath * path,
	gboolean path_currently_selected,
	gpointer userdata) {
	
	GtkTreeIter iter;
	long data_index;
	int data_len;
	time_t t_cap;
	char buf[BUF_SZ];

    if ((!path_currently_selected) && gtk_tree_model_get_iter(model, &iter, path)) {
		
		gchar key[20];
    	int no;
      	gtk_tree_model_get(model, &iter, LIST_NO, &no, -1);
      	
      	FILE * fp_index, * fp_data;
      	
      	if((fp_index = fopen("capture_index.dat", "rb")) == NULL) {
			perror("can't open capture_index.dat");
			return -1;
		}
	
		if((fp_data = fopen("capture_data.dat", "rb")) == NULL) {
			perror("can't open capture_data.dat");
			return -1;
		}
		
		//get data index
		fseek(fp_index, (no-1)*(sizeof(long) + sizeof(time_t) + sizeof(int)), SEEK_SET);
		fread(&data_index, sizeof(long), 1, fp_index);
		fread(&data_len, sizeof(int), 1, fp_index);
		fread(&t_cap, sizeof(time_t), 1, fp_index);
		
		fseek(fp_data, data_index, SEEK_SET);
		fread(buf, data_len, 1, fp_data);
		
		fclose(fp_index);
		fclose(fp_data);
		
    	GtkWidget *list2 = lookup_widget(GTK_WIDGET(userdata), "treeview_3rd");
    	GtkWidget *txt = lookup_widget(GTK_WIDGET(userdata), "textview");
    	
    	show_detail(list2, buf, no, data_len, t_cap);
    	show_binary(txt, buf, data_len);
    }

    return TRUE; /* allow selection state to change */
}




void
init_list(GtkWidget *list)
{

  GtkCellRenderer *renderer;
  GtkTreeViewColumn *column;
  GtkListStore *store;
  GtkTreeModel* m;
  GtkTreeSelection *selection;

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("NO", renderer, "text", LIST_NO, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  gtk_tree_view_column_add_attribute(column, renderer, "foreground", LIST_COLOR);
  gtk_tree_view_column_add_attribute(column, renderer, "cell-background", LIST_BG);
  g_object_set(renderer, "foreground-set", TRUE, "cell-background-set", TRUE, "ypad", 0, NULL); 
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Time", renderer, "text", LIST_TIME, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  gtk_tree_view_column_add_attribute(column, renderer, "foreground", LIST_COLOR);
  gtk_tree_view_column_add_attribute(column, renderer, "cell-background", LIST_BG);
  g_object_set(renderer, "foreground-set", TRUE, "cell-background-set", TRUE, "ypad", 0, NULL); 
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Source", renderer, "text", LIST_SRC, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  gtk_tree_view_column_add_attribute(column, renderer, "foreground", LIST_COLOR);
  gtk_tree_view_column_add_attribute(column, renderer, "cell-background", LIST_BG);
  g_object_set(renderer, "foreground-set", TRUE, "cell-background-set", TRUE, "ypad", 0, NULL); 
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Destination", renderer, "text", LIST_DST, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  gtk_tree_view_column_add_attribute(column, renderer, "foreground", LIST_COLOR);
  gtk_tree_view_column_add_attribute(column, renderer, "cell-background", LIST_BG);
  g_object_set(renderer, "foreground-set", TRUE, "cell-background-set", TRUE, "ypad", 0, NULL); 
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Protocol", renderer, "text", LIST_PROTO, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  gtk_tree_view_column_add_attribute(column, renderer, "foreground", LIST_COLOR);
  gtk_tree_view_column_add_attribute(column, renderer, "cell-background", LIST_BG);
  g_object_set(renderer, "foreground-set", TRUE, "cell-background-set", TRUE, "ypad", 0, NULL);    
  
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Information", renderer, "text", LIST_INFO, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);
  gtk_tree_view_column_add_attribute(column, renderer, "foreground", LIST_COLOR);
  gtk_tree_view_column_add_attribute(column, renderer, "cell-background", LIST_BG);
  g_object_set(renderer, "foreground-set", TRUE, "cell-background-set", TRUE, "ypad", 0, NULL);  
	
  store = gtk_list_store_new(
  	N_COLUMNS, 
  	G_TYPE_INT, 
  	G_TYPE_FLOAT, 
  	G_TYPE_STRING, 
  	G_TYPE_STRING, 
  	G_TYPE_STRING, 
  	G_TYPE_STRING,
  	G_TYPE_STRING,
  	G_TYPE_STRING);

  gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(store));
  
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
  gtk_tree_selection_set_select_function(selection, view_selection_func, list, NULL);
  
  m = GTK_TREE_MODEL(store);
  g_signal_connect ((gpointer)m, "row-inserted", G_CALLBACK (on_model_row_inserted), (gpointer)list);

  g_object_unref(store);
}

void add_to_list(
	GtkWidget *list, 
	int no, 
	float time, 
	const gchar * src,
	const gchar * dst,
	const gchar * proto,
	const gchar * info,
	const gchar * color,
	const gchar * bg)
{
  GtkListStore *store;
  GtkTreeIter iter;

  store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
  gtk_list_store_append(store, &iter);
  gtk_list_store_set(store, &iter, 
  	LIST_NO, no,
  	LIST_TIME, time,
  	LIST_SRC, src,
  	LIST_DST, dst,
  	LIST_PROTO, proto,
  	LIST_INFO, info,
  	LIST_COLOR, color,
  	LIST_BG, bg, -1);
}


#endif

