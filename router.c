#include <arpa/inet.h> 
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"
#include "protocols.h"
#include "queue.h"

#define MAX_RTABLE_ENTRIES 80000
#define MAX_ARP_ENTRIES 100

struct trie_node {
	struct trie_node *left;
	struct trie_node *right;
	struct route_table_entry *route;
};

struct waiting_packet {
	char buf[MAX_PACKET_LEN];
	size_t len;
	int interface;
	uint32_t next_hop;
};

struct route_table_entry *rtable;
int rtable_len;
struct arp_table_entry *arp_table;
int arp_table_len;
struct trie_node *root;
queue waiting_packets;

struct trie_node *new_node()
{
	struct trie_node *node = malloc(sizeof(struct trie_node));
	DIE(node == NULL, "malloc");
	node->left = NULL;
	node->right = NULL;
	node->route = NULL;
	return node;
}

int get_mask_len(uint32_t mask)
{
	mask = ntohl(mask);
	int contor = 0;
	while (mask) {
		contor += (mask & 1);
		mask >>= 1;
	}
	return contor;
}

void add_route(struct route_table_entry *entry)
{
	struct trie_node *node = root;
	uint32_t prefix = ntohl(entry->prefix);
	int len = get_mask_len(entry->mask);

	for (int i = 31; i >= 32 - len; i--) {
		int bit = (prefix >> i) & 1;
		if (bit == 0) {
			if (node->left == NULL) {
				node->left = new_node();
			}
			node = node->left;
		} else {
			if (node->right == NULL) {
				node->right = new_node();
			}
			node = node->right;
		}
	}
	node->route = entry;
}

void build_trie()
{
	root = new_node();
	for (int i = 0; i < rtable_len; i++) {
		add_route(&rtable[i]);
	}
}

struct route_table_entry *get_best_route(uint32_t dest_ip)
{
	struct trie_node *node = root;
	struct route_table_entry *best = NULL;
	uint32_t ip = ntohl(dest_ip);

	for (int i = 31; i >= 0; i--) {
		if (node->route != NULL) {
			best = node->route;
		}
		int current_bit = (ip >> i) & 1;
		if (current_bit == 0) {
			if (node->left == NULL) {
				return best;
			}
			node = node->left;
		} else {
			if (node->right == NULL) {
				return best;
			}
			node = node->right;
		}
	}
	if (node->route != NULL) {
		return node->route;
	}
	return best;
}

struct arp_table_entry *get_arp_entry(uint32_t ip)
{
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

void add_arp_entry(uint32_t ip, uint8_t *mac)
{
	struct arp_table_entry *entry = get_arp_entry(ip);
	if (entry != NULL) {
		memcpy(entry->mac, mac, 6);
		return;
	}
	if (arp_table_len < MAX_ARP_ENTRIES) {
		arp_table[arp_table_len].ip = ip;
		memcpy(arp_table[arp_table_len].mac, mac, 6);
		arp_table_len++;
	}
}

void add_packet_in_queue(char *buf, size_t len, int interface, uint32_t next_hop)
{
	struct waiting_packet *packet = malloc(sizeof(struct waiting_packet));
	DIE(packet == NULL, "malloc");

	memcpy(packet->buf, buf, len);
	packet->len = len;
	packet->interface = interface;
	packet->next_hop = next_hop;
	queue_enq(waiting_packets, packet);
}

void send_waiting_packets(uint32_t ip)
{
	struct arp_table_entry *arp = get_arp_entry(ip);
	if (arp == NULL) {
		return;
	}
	queue new_queue = create_queue();
	while (!queue_empty(waiting_packets)) {
		struct waiting_packet *packet = queue_deq(waiting_packets);
		if (packet->next_hop == ip) {
			struct ether_hdr *eth_hdr = (struct ether_hdr *)packet->buf;
			memcpy(eth_hdr->ethr_dhost, arp->mac, 6);
			get_interface_mac(packet->interface, eth_hdr->ethr_shost);
			send_to_link(packet->len, packet->buf, packet->interface);
			free(packet);
		} else {
			queue_enq(new_queue, packet);
		}
	}
	free(waiting_packets);
	waiting_packets = new_queue;
}

int check_if_router_ip(uint32_t ip)
{
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		if (inet_addr(get_interface_ip(i)) == ip) {
			return 1;
		}
	}
	return 0;
}

void send_arp_request(uint32_t target_ip, int interface)
{
	char arp_buf[MAX_PACKET_LEN];
	struct ether_hdr *eth_hdr = (struct ether_hdr *)arp_buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(arp_buf + sizeof(struct ether_hdr));

	memset(eth_hdr->ethr_dhost, 0xFF, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);

	eth_hdr->ethr_type = htons(0x0806);
	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1);
	
	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	memset(arp_hdr->thwa, 0, 6);
	arp_hdr->tprotoa = target_ip;
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_buf, interface);
}

void send_arp_reply(char *buf, int interface)
{
	char arp_buf[MAX_PACKET_LEN];
	struct ether_hdr *old_eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *old_arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)arp_buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(arp_buf + sizeof(struct ether_hdr));

	memcpy(eth_hdr->ethr_dhost, old_eth_hdr->ethr_shost, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);

	eth_hdr->ethr_type = htons(0x0806);
	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(2);

	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	memcpy(arp_hdr->thwa, old_arp_hdr->shwa, 6);
	arp_hdr->tprotoa = old_arp_hdr->sprotoa;
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_buf, interface);
}

void send_icmp_reply(char *buf, size_t len, int interface)
{
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + ip_hdr->ihl * 4);
	uint8_t aux_mac[6];
	uint32_t aux_ip;

	memcpy(aux_mac, eth_hdr->ethr_shost, 6);
	memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
	memcpy(eth_hdr->ethr_dhost, aux_mac, 6);

	aux_ip = ip_hdr->source_addr;
	ip_hdr->source_addr = ip_hdr->dest_addr;
	ip_hdr->dest_addr = aux_ip;
	ip_hdr->ttl = 64;
	icmp_hdr->mtype = 0;
	icmp_hdr->mcode = 0;
	icmp_hdr->check = 0;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
	send_to_link(len, buf, interface);
}

void send_icmp_error(char *buf, uint8_t type, uint8_t code)
{
	char new_buf[MAX_PACKET_LEN];
	struct ip_hdr *old_ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct route_table_entry *route = get_best_route(old_ip_hdr->source_addr);
	if (route == NULL) {
		return;
	}
	uint32_t next_hop;
	if (route->next_hop != 0) {
		next_hop = route->next_hop;
	} else {
		next_hop = old_ip_hdr->source_addr;
	}
	struct ether_hdr *eth_hdr = (struct ether_hdr *)new_buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(new_buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	ip_hdr->ver = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	ip_hdr->id = htons(1);
	ip_hdr->frag = 0;
	ip_hdr->ttl = 64;
	ip_hdr->proto = 1;
	ip_hdr->source_addr = inet_addr(get_interface_ip(route->interface));
	ip_hdr->dest_addr = old_ip_hdr->source_addr;
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = code;
	icmp_hdr->check = 0;
	icmp_hdr->un_t.gateway_addr = 0;

	char *data = new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
	memcpy(data, old_ip_hdr, sizeof(struct ip_hdr) + 8);
	size_t icmp_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));
	
	eth_hdr->ethr_type = htons(0x0800);
	struct arp_table_entry *arp = get_arp_entry(next_hop);
	if (arp == NULL) {
		add_packet_in_queue(new_buf, icmp_len, route->interface, next_hop);
		send_arp_request(next_hop, route->interface);
		return;
	}

	memcpy(eth_hdr->ethr_dhost, arp->mac, 6);
	get_interface_mac(route->interface, eth_hdr->ethr_shost);
	
	send_to_link(icmp_len, new_buf, route->interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_ENTRIES);
	DIE(rtable == NULL, "malloc");
	arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_ENTRIES);
	DIE(arp_table == NULL, "malloc");

	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;
	waiting_packets = create_queue();
	build_trie();
	char **interfaces = &argv[2];
	int interfaces_count = argc - 2;
	init(interfaces, interfaces_count);

	while (1) {
		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_link");
		if (len < sizeof(struct ether_hdr)) {
			continue;
		}
		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		uint8_t interface_mac[6];
		uint8_t broadcast[6];
		get_interface_mac(interface, interface_mac);
		memset(broadcast, 0xFF, 6);

		if (memcmp(eth_hdr->ethr_dhost, interface_mac, 6) != 0 &&
   			 memcmp(eth_hdr->ethr_dhost, broadcast, 6) != 0) {
    		continue;
		}

		if (ntohs(eth_hdr->ethr_type) == 0x0806) {
			if (len < sizeof(struct ether_hdr) + sizeof(struct arp_hdr)) {
				continue;
			}
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			add_arp_entry(arp_hdr->sprotoa, arp_hdr->shwa);
			if (ntohs(arp_hdr->opcode) == 1) {
				if (arp_hdr->tprotoa == inet_addr(get_interface_ip(interface))) {
					send_arp_reply(buf, interface);
				}
			}
			if (ntohs(arp_hdr->opcode) == 2) {
				send_waiting_packets(arp_hdr->sprotoa);
			}
			continue;
		}
		if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr)) {
			continue;
		}
		struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
		if (ntohs(eth_hdr->ethr_type) != 0x0800) {
			continue;
		}
		uint16_t check = ntohs(ip_hdr->checksum);
		ip_hdr->checksum = 0;
		if (checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4) != check) {
			continue;
		}
		ip_hdr->checksum = htons(check);
		if (check_if_router_ip(ip_hdr->dest_addr)) {
			if (ip_hdr->proto == 1) {
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + ip_hdr->ihl * 4);
				if (icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0) {
					send_icmp_reply(buf, len, interface);
				}
			}
			continue;
		}
		struct route_table_entry *route = get_best_route(ip_hdr->dest_addr);
		if (route == NULL) {
			send_icmp_error(buf, 3, 0);
			continue;
		}
		if (ip_hdr->ttl <= 1) {
			send_icmp_error(buf, 11, 0);
			continue;
		}
		ip_hdr->ttl--;
		ip_hdr->checksum = 0;
		ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4));
		uint32_t next_hop;
		if (route->next_hop != 0) {
			next_hop = route->next_hop;
		} else {
			next_hop = ip_hdr->dest_addr;
		}
		struct arp_table_entry *arp = get_arp_entry(next_hop);
		if (arp == NULL) {
			add_packet_in_queue(buf, len, route->interface, next_hop);
			send_arp_request(next_hop, route->interface);
			continue;
		}
		memcpy(eth_hdr->ethr_dhost, arp->mac, 6);
		get_interface_mac(route->interface, eth_hdr->ethr_shost);
		send_to_link(len, buf, route->interface);
	}
}
