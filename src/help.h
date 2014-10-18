

int str_cmp_cc(void * p1, void * p2, int len, gboolean case_sensitive) {
	u_int8_t * p01 = (u_int8_t *)p1;
	u_int8_t * p02 = (u_int8_t *)p2;
	int i;
	
	for(i=0; i<len; i++) {
		if(case_sensitive) {
			if(p01[i] != p02[i])
				return p01[i] - p02[i];
		} else {
			int t01, t02;
			
			//turn lower case to upper case
			t01 = (p01[i] > 96 && p01[i] < 123) ? p01[i] - 32 : p01[i];
			t02 = (p02[i] > 96 && p02[i] < 123) ? p02[i] - 32 : p02[i];
			
			if(t01 != t02)
				return t01 - t02;
		}
	}
	
	return 0;
}

// return the first char position of found string, if found
int str_idx_cc(char * p1, char * p2, int len1, int len2, gboolean case_sensitive) {
	
	if(len2 > len1) {
		printf("len2 > len1");
		return -1;
	}
	
	int i = 0, match_bytes = 0;
	int val1, val2;
	
	for(i=0; (i<len1) && (match_bytes<len2); i++) {
		if(case_sensitive) {
		
			if(p1[i] == p2[match_bytes]) match_bytes ++;
			else match_bytes = 0;
				
		} else {
		
			val1 = (p1[i] > 96 && p1[i] < 123) ? p1[i] - 32 : p1[i];
			val2 = (p2[i] > 96 && p2[i] < 123) ? p2[i] - 32 : p2[i];
			
			if(val1 == val2) match_bytes ++;
			else match_bytes = 0;
			
		}
	}
	
	if(len1 == i) return -1;
	return i-len2;
}

char * str_cpy_cc(char * to, char * from, int len) {
	int i;
	
	for(i=0; i<len; i++) {
		to[i] = from[i];
	}
	
	to[i] = 0;
	
	return to;
}


int get_line_cc(char * ln, char * buf, int max_len) {
	
	int i = 0;
	while('\n' != buf[i] && (max_len == -1 || i < max_len)) {
		ln[i] = buf[i];
		i++;
	}
	
	return (i == max_len) ? -1 : i;
}


void str_cat_cc(char * str, char * sub, int len) {
	int i;
	for(i=0; i<len; i++) {
		str[i] = sub[i];
	}
	str[i] = 0;
}


char * eth_ntop_cc(void * eth_addr, char * eth_str) {
	u_int8_t * addr = (u_int8_t *)eth_addr;
	
	sprintf(eth_str, "%02x:%02x:%02x:%02x:%02x:%02x", 
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
		
	return eth_str;
}






