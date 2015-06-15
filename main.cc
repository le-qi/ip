#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "ipsum.h"

#define INFINITY 16
#define MAX_MSG_LENGTH 512
#define MAX_BACK_LOG 5
#define MAX_TTL 12
#define MAX_ENTRIES 64;
#define IP_HEADER_LENGTH 5
#define MAX_IP_BYTES 65536
#define MTU 1400  //in bytes

using namespace std;

struct entry {
	uint32_t cost;
	uint32_t address;
};

struct route {
	uint32_t dest;
	uint32_t next_hop;
	uint32_t cost;
	uint32_t ttl;
};

struct interface {
	uint32_t num;
	sockaddr_in addr;
	uint32_t my_vip;
	uint32_t other_vip;
	string status;
};

struct ip_packet {
	struct ip header;
	char payload[MAX_IP_BYTES - (IP_HEADER_LENGTH * 4)];
};

class RIPPacket {

public:
	uint16_t command;
	uint16_t num_entries;
	entry * entries;
	RIPPacket (uint16_t _command) : command(_command){
		entries = (entry*) malloc(sizeof(*entries));
		num_entries = 0;
	}
	~RIPPacket() {
		free(entries);
	}
	void addEntry(uint32_t address, uint32_t cost) {
		entry e;
		e.address = address;
		e.cost = cost;
		num_entries++;
		entries = (entry *) realloc(entries, (num_entries+1)*sizeof(entry));
		entries[num_entries-1] = e;
	}
};

void read_text(char *text);
int rip();
int user();
int receiver();
void ifconfig();
void print_route(route *r);
void update_routes(RIPPacket * rip, uint32_t other_ip);
bool merge_routes(uint32_t dest, uint32_t cost, uint32_t other_ip);
void routes();
void down(uint32_t num);
void up(uint32_t num);
void print_buffer(char * data);
string cast_ntoa(uint32_t n);
uint32_t cast_aton(char *a);
bool costInfinite(uint32_t address);
void serialize(RIPPacket * packet, char * payload);
RIPPacket * deserialize(char* data);
int package_and_send(char * payload, uint8_t type, uint32_t dest, uint32_t ttl, bool test);
int process_ip_packet(ip_packet * packet, bool test);
void print_ip_packet(void * ipp);
void print_ip_header (void * iph);

void print_route_ttl();
void decrement_route_TTL();
void send_requests_all();
void triggered_updates();
RIPPacket * create_rip_packet(uint16_t command, uint32_t send_ip);
void handle_rip_packet(RIPPacket* packet, uint32_t ip);
void print_rip_packet(RIPPacket* packet);
RIPPacket * fakePacketa(uint16_t command);
RIPPacket * fakePacketb(uint16_t command);
RIPPacket * fakePacketc(uint16_t command);

uint32_t my_ip_to_other(uint32_t my_ip);
uint32_t other_ip_to_my(uint32_t my_ip);
interface *route_to_interface(route *r);
uint32_t vip_to_interface(uint32_t ip);
bool destination_is_interface(uint32_t ip);

sockaddr_in my_ip_addr;
vector<route> route_table;
vector<interface> my_interfaces;
pthread_mutex_t lock;
u_short ident = 0;
int sock_send;
char localhost[11] = "127.0.0.1\0";

int main(int argc, char ** argv)
{
	pthread_t rip_thread;
	pthread_t receiver_thread;
	pthread_mutex_init(&lock, NULL);

	if (argc < 2) {
		fprintf(stderr, "usage: prog file.txt\n");
		return 0;
	}

	read_text(argv[1]);

	pthread_mutex_lock(&lock);
	pthread_create(&receiver_thread, NULL, (void *(*)(void *)) receiver, NULL);
	pthread_create(&rip_thread, NULL, (void *(*)(void *)) rip, NULL);
	return user();
}

/* Thread to send RIP messages every five seconds */
int rip() {

	time_t oldtime_one = time(NULL);
	time_t oldtime_five = time(NULL);
	time_t newtime;

	pthread_mutex_lock(&lock);
	send_requests_all();
	pthread_mutex_unlock(&lock);

	while (1) {
		newtime = time(NULL);
		if (difftime(newtime, oldtime_five) > 5) {
			pthread_mutex_lock(&lock);
			send_requests_all();
			oldtime_five += 5;
			pthread_mutex_unlock(&lock);
		}

		if (difftime(newtime, oldtime_one) > 1) {
			decrement_route_TTL();
			oldtime_one++;
		}
	}
	return 0;
}

/* Thread to continuously receive messages */
int receiver() {

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	char this_packet[65536];

	unsigned int recv_len;
	unsigned int client_addr_len;

	if ((sock_send = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Create socket error:\n");
		pthread_mutex_unlock(&lock);
		return -1;
	}

	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = my_ip_addr.sin_port;

	if ((bind(sock_send, (struct sockaddr*) &server_addr, sizeof(server_addr))) < 0) {
		perror("Bind error:\n");
		pthread_mutex_unlock(&lock);
		return -1;
	}

	pthread_mutex_unlock(&lock);

	while (1) {

		memset(this_packet, 0, 65536);

		if ((recv_len = recvfrom(sock_send, (void *) this_packet, sizeof(this_packet), 0,
				(struct sockaddr *) &client_addr, &client_addr_len)) < 0) {
			perror("Receive error:\n");
			return -1;
		} 

		pthread_mutex_lock(&lock);

		bool reject = false;
		for (unsigned int i = 0; i < my_interfaces.size(); i++) {
			if (my_interfaces[i].addr.sin_port == client_addr.sin_port) {
				if (my_interfaces[i].status == "down") {
					reject = true;
				}
			}
		}
		if (reject) {
			pthread_mutex_unlock(&lock);
			continue;
		}

		ip_packet *ipp = (ip_packet *) this_packet;

		if (process_ip_packet(ipp, false) == -1) {
			perror("Process IP packet error\n");
			pthread_mutex_unlock(&lock);
			return -1;
		}
		pthread_mutex_unlock(&lock);

	}

	close(sock_send);
	return 0;
}

bool costInfinite(uint32_t address) {
	bool hasNonInfiniteCost = false;
	for (unsigned int i=0;i<route_table.size();i++) {
		if (route_table[i].dest == address && route_table[i].cost < INFINITY) {
			hasNonInfiniteCost = true;
		}
	}
	return !hasNonInfiniteCost;
}

/* Prints out char array containing RIPPacket (debugging) */
void print_buffer(char * data) {

	cout << "print_buffer: SERIALIZED: " << endl;
	uint16_t *test = (uint16_t *) data;
	cout << "print_buffer: command is "<<*test << endl;
	test++;
	uint16_t n = *test;
	cout << "print_buffer: num_entries is "<<*test << endl;
	test++;
	uint32_t *e = (uint32_t*) test;
	for (unsigned int i = 0; i < n; i++) {
		cout << *e << " ";
		e++;
		cout << *e << endl;
		e++;
	}
	cout << endl;

}

/* Serializes RIPPacket into character buffer to send over network */
void serialize(RIPPacket * msgPacket, char * data) {
	uint16_t *q = (uint16_t *) data;
	*q = msgPacket->command;
	q++;
	*q = msgPacket->num_entries;
	q++;
	uint32_t *r = (uint32_t *) q;
	for (int i = 0;i < msgPacket->num_entries; i++) {
		*r = msgPacket->entries[i].cost;
		r++;
		*r = msgPacket->entries[i].address;
		r++;
	}
}

/* Retrieves RIPPacket from character buffer */
RIPPacket* deserialize(char *data) {
	uint16_t *q = (uint16_t *) data;
	uint16_t com = *q;
	RIPPacket *msgPacket = new RIPPacket(com);
	q++;
	uint16_t num = *q;
	q++;
	uint32_t *r = (uint32_t *) q;
	for (int i = 0; i < num; i++) {
		uint32_t cost = *r;
		r++;
		uint32_t address = *r;
		r++;
		msgPacket->addEntry(address, cost);
	}
	return msgPacket;
}

/* Prints out entire IP packet (debugging) */
void print_ip_packet(void * ipp) {

	cout << "PRINTING FULL PACKET: " << endl;
	print_ip_header(ipp);
	ip * ptr = (ip *) ipp;
	ptr++;
	print_buffer((char *) ptr);

}

/* Prints IP header in human readable form (debugging) */
void print_ip_header (void * iph) {

	ip *tester = (ip *) iph;

	cout << "PRINT OUT IP HEADER: " << endl;
	cout << "IP Version: " << tester->ip_v << endl;
	cout << "Header Length: " << tester->ip_hl << endl;
	cout << "TOS: " << (int) tester->ip_tos << endl;
	cout << "Length: " << (int) tester->ip_len << endl;
	cout << "Ident: " << (int) tester->ip_id << endl;
	cout << "Offset: " << (int) tester->ip_off << endl;
	cout << "TTL: " << (int) tester->ip_ttl << endl;
	cout << "Protocol: " << (int) tester->ip_p << endl;
	cout << "Destination Addr: " << cast_ntoa(tester->ip_src.s_addr) << endl;
	cout << "Source Addr: " << cast_ntoa(tester->ip_dst.s_addr) << endl;
	cout << "Checksum: " << tester->ip_sum << endl;
}

/* Prints router's information about interfaces (debugging) */
void print_my_interfaces() {
	for (unsigned int i=0;i<my_interfaces.size();i++) {
		cout << "entry i = " <<i<<"\n";
		cout << "num = " << my_interfaces[i].num<< ", addr = "<<cast_ntoa(my_interfaces[i].addr.sin_addr.s_addr) << ", my_vip = "<<cast_ntoa(my_interfaces[i].my_vip) <<", other_vip = "<<cast_ntoa(my_interfaces[i].other_vip) << ", status = "<<my_interfaces[i].status <<"\n";
	}
}

/* Prints local route table (debugging) */
void print_route_table() {
	for (unsigned int i=0;i<route_table.size();i++) {
		cout << "entry i = " <<i<<"\n";
		cout << "dest = "<<route_table[i].dest<<", next_hop = "<<route_table[i].next_hop<<", cost = "<<route_table[i].cost<<", ttl = "<<route_table[i].ttl<<"\n";
	}
}

/* Print IP packet specifics in readable form (debugging) */
void print_ip_packet(char * ip, bool isRIP) {
  cout << "print_ip_packet: printing HEADER:\n";
  unsigned int *q = (unsigned int*) ip;
  cout << "header.ip_hl is " <<(int) *q <<"\n";
  q++;
  cout <<  "header.ip_v is " <<(int)*q << "\n";
  q++;
  uint8_t *r = (uint8_t*) q;
  cout <<  "header.ip_tos is "<< (int)*r << "\n";
  r++;
  uint16_t *s = (uint16_t*) r;
  cout <<  "header.ip_len is " <<(int) *s << "\n";
  s++;
  cout << "header.ip_id is "<<(int) *s << "\n";
  s++;
  cout <<  "header.ip_off is " <<(int) *s << "\n";
  s++;
  uint8_t *t = (uint8_t*) s;
  cout <<  "header.ip_ttl is " <<(int)*t<< "\n";
  t++;
  cout <<  "header.ip_p is " <<(int)*t<< "\n";
  t++;
  uint16_t *u = (uint16_t*) t;
  cout <<  "header.ip_sum is "<<(int)*u << "\n";
  u++;
  struct in_addr * v = (struct in_addr*) u;
  cout <<  "header.ip_src.s_addr is "<<v->s_addr << "\n";
  v++;
  cout <<  "header.ip_dst.s_addr is "<<v->s_addr << "\n";
  v++;
  
  cout << "print_ip_packet: printing PAYLOAD, isRIP = " << isRIP <<"\n";
  if (isRIP) {

  } else {
    cout << "is not rip --> normal message: \n";
    cout << string((char*)v) <<"\n";
  }
}

/* 	Attaches IP header to data found in payload. Data to be sent to virtual IP address found
	in dest, and the type specifies whether the packet sent is an RIP message. The test param
	was used for debugging purposes.
 */
int package_and_send(char * payload, uint8_t type, uint32_t dest, uint32_t ttl, bool test) {

  char * buffer = (char*) malloc(MTU*sizeof(*buffer));
	char * payload_start = (char*) malloc(MTU*sizeof(*payload_start));
	ip header;

	header.ip_v = IPVERSION;
	header.ip_hl = IP_HEADER_LENGTH;
	header.ip_tos = IPTOS_RELIABILITY;

	if (type == 200) {
		RIPPacket * rip_packet = (RIPPacket *) payload;
		header.ip_len = (uint16_t) (IP_HEADER_LENGTH * 4 + 4 + rip_packet->num_entries * 8);
	}
	else {
		header.ip_len = (uint16_t) (IP_HEADER_LENGTH * 4 + strlen(payload));
	}
	header.ip_id = ident;
	header.ip_off = 0;
	header.ip_ttl = ttl;
	header.ip_p = type;
	header.ip_dst.s_addr = dest;
	header.ip_src.s_addr = other_ip_to_my(dest);
	header.ip_sum = (uint16_t) ip_sum((char *) &header, IP_HEADER_LENGTH * 4);

	memcpy(buffer, (void *) &header, sizeof(header));
	payload_start = buffer + sizeof(header);

	memcpy(payload_start, (void *) payload, header.ip_len - IP_HEADER_LENGTH * 4);

	//look up route
	for (unsigned int i = 0; i < route_table.size(); i++) {

		route thisRoute = route_table[i];

		if (thisRoute.dest == dest) {

			interface *next_interface = route_to_interface(&thisRoute);

			sockaddr_in nextHopRealIP;

			nextHopRealIP.sin_addr.s_addr = htonl(INADDR_ANY);
			if (next_interface == NULL) {
				nextHopRealIP.sin_family = my_ip_addr.sin_family;
				nextHopRealIP.sin_port = my_ip_addr.sin_port;
			}
			else {
				if (next_interface->status == "down") {
					return 0;
				}
				nextHopRealIP.sin_family = next_interface->addr.sin_family;
				nextHopRealIP.sin_port = next_interface->addr.sin_port;
			}

			if (!test) {
				if ((sendto(sock_send, (void *) buffer, header.ip_len, 0, (struct sockaddr *) &nextHopRealIP, sizeof(nextHopRealIP))) < 0) {
					perror("Forwarding error:\n");
					return -1;
				}
				return 0;
			}
		}
	}

	perror("this packet's destination is not in the routing table\n");
	return 0;

}

/* 	Called when IP packet is received. Determines whether packet should be forwarded to
	another router or whether current router is final destination.
 */
int process_ip_packet(ip_packet * this_packet, bool test) {

	char* payload = this_packet->payload;
	int payload_length = strlen(payload);

	if (test) {
		cout << "before checksum, payload is " << payload <<", payload_length is "<< payload_length<<"\n";
	}

	if (this_packet->header.ip_sum != (uint16_t) ip_sum((char *) &(this_packet->header), IP_HEADER_LENGTH * 4)) {
		perror("checksum incorrect!\n");
		return -1;
	}

	if ((uint32_t) this_packet->header.ip_p == 200) { //if it's an rip message: update routing table
		RIPPacket * packet = deserialize(payload);
		handle_rip_packet(packet, this_packet->header.ip_dst.s_addr);
		delete packet;
	} else  { //if protocol == 0->receive test data
		//it's a regular message
		if (destination_is_interface(this_packet->header.ip_dst.s_addr)) {
			cout << payload <<"\n";
		} else if ((int)this_packet->header.ip_ttl <= 0) {  //if ttl less than 0 --> drop packet
			//do nothing
			cout << "ttl < 0 --> drop packet\n";
		} else if (INFINITY == costInfinite(this_packet->header.ip_src.s_addr)) { //if the cost = infinity
			//do nothing
			cout << "cost = infinity \n";
		} else {
			//send the packet to next hop
			this_packet->header.ip_ttl --;
			package_and_send(payload, this_packet->header.ip_p, this_packet->header.ip_dst.s_addr, this_packet->header.ip_ttl, false);
		}
	}
	return 0;
}

/* Thread for user to bring interfaces up and down and query information from the router. */
int user() {

	string response;
	string command;
	string argument;
	string send_ip;
	string delim = " ";
	int index;

	while (1) {
		getline(cin, response);
		index = response.find(delim);

		if (index == -1) {
			command = response;
		}
		else {
			command = response.substr(0, index);
		}

		if (command == "ifconfig") {
			ifconfig();
		}
		else if (command == "routes") {
			routes();
		}
		else if (command == "down") {
			argument = response.substr(index + 1);
			down((uint32_t) atoi(argument.c_str()));
		}
		else if (command == "up") {
			argument = response.substr(index + 1);
			up((uint32_t) atoi(argument.c_str()));
		}
		else if (command == "send") {
			argument = response.substr(index + 1);
			index = argument.find(delim);
			if (index == -1) {
				continue;
			}
			send_ip = argument.substr(0, index);
			argument = argument.substr(index + 1);
			package_and_send((char *) argument.c_str(), 0, cast_aton((char *) send_ip.c_str()), INFINITY, false);
		}
		else if (command == "ttl") {
			print_route_ttl();
		}
	}
	return 0;
}

/* Displays router's network interfaces with other routers and their status */
void ifconfig() {

	pthread_mutex_lock(&lock);
	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		interface ifc = my_interfaces.at(i);
		cout << ifc.num << " " << cast_ntoa(ifc.my_vip) << " " << cast_ntoa(ifc.other_vip) << " " << ifc.status << " " << endl;
	}
	pthread_mutex_unlock(&lock);

}

/* Displays route information for all other virtual IP addresses in network. */
void routes()
{
	pthread_mutex_lock(&lock);
	for (unsigned int i = 0; i < route_table.size(); i++) {
		route r = route_table[i];
		interface *ifc = route_to_interface(&r);
		if (r.cost > 0 && ifc != NULL) {
			cout << cast_ntoa(r.dest) << " " << cast_ntoa(r.next_hop) << " " << route_to_interface(&r)->num << " " << r.cost << " " << endl;
		}
	}
	pthread_mutex_unlock(&lock);
}

/* Brings an interface down. */
void down(uint32_t num) {

	pthread_mutex_lock(&lock);
	interface *ifc;

	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		if (my_interfaces[i].num == num) {
			ifc = &my_interfaces[i];
		}
	}

	if (ifc == NULL) {
		cout << "Interface " << num << " not found." << endl;
		pthread_mutex_unlock(&lock);
		return;
	}

	if (ifc->status == "down") {
		cout << "Interface " << num << " down." << endl;
		pthread_mutex_unlock(&lock);
		return;
	}

	ifc->status = "down";
	for (unsigned int i = 0; i < route_table.size(); i++) {
		if (route_table[i].next_hop == ifc->other_vip) {
			route_table[i].cost = INFINITY;
		}
	}

	triggered_updates();
	pthread_mutex_unlock(&lock);

	cout << "Interface " << num << " down." << endl;

}

/* Brings a down interface back up. */
void up(uint32_t num) {

	pthread_mutex_lock(&lock);

	interface *ifc;

	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		if (my_interfaces[i].num == num) {
			ifc = &my_interfaces[i];
		}
	}

	if (ifc == NULL) {
		cout << "Interface " << num << " not found." << endl;
		pthread_mutex_unlock(&lock);
		return;
	}

	if (ifc->status == "up") {
		cout << "Interface " << num << " up." << endl;
		pthread_mutex_unlock(&lock);
		return;
	}

	ifc->status = "up";
	for (unsigned int i = 0; i < route_table.size(); i++) {
		if (route_table[i].dest == ifc->my_vip) {
			route_table[i].next_hop = ifc->my_vip;
			route_table[i].cost = 0;
			route_table[i].ttl = MAX_TTL;
		}
		else if (route_table[i].dest == ifc->other_vip) {
			route_table[i].next_hop = ifc->other_vip;
			route_table[i].cost = 1;
			route_table[i].ttl = MAX_TTL;
		}
	}
	triggered_updates();
	pthread_mutex_unlock(&lock);

	cout << "Interface " << num << " up." << endl;

}

/* Fake packet A sent for testing. */
RIPPacket * fakePacketa(uint16_t command)
{
	RIPPacket * packet = new RIPPacket(command);
	packet->addEntry(2639885322, 0);
	packet->addEntry(1235749386, 0);
	return packet;
}

/* Fake packet B sent for testing. */
RIPPacket * fakePacketb(uint16_t command)
{
	RIPPacket * packet = new RIPPacket(command);
	packet->addEntry(1235749386, 0);
	packet->addEntry(2097359370, 0);
	packet->addEntry(2639885322, 1);
	packet->addEntry(604366350, 1);
	return packet;
}

/* Fake packet C sent for testing. */
RIPPacket * fakePacketc(uint16_t command)
{
	RIPPacket * packet = new RIPPacket(command);
	packet->addEntry(604366350, 0);
	packet->addEntry(2097359370, 1);
	return packet;
}

/* Decreases time to live for a route every second. If TTL is 0, the route is inactive and cost is set to infinity. */
void decrement_route_TTL() {

	for (unsigned int i = 0; i < route_table.size(); i++) {
		bool decremented = false;
		if (route_table[i].ttl > 0 && !destination_is_interface(route_table[i].dest)) {
			if (route_table[i].cost != 0) {
				route_table[i].ttl--;
				decremented = true;
			}
		}
		if (route_table[i].ttl == 0 && decremented) {
			route_table[i].cost = INFINITY;
			// down_interface->status = "down";
			triggered_updates();
		}
	}
}

/* Print time to live values (debugging). */
void print_route_ttl()
{
	for (unsigned int i = 0; i < route_table.size(); i++) {
		cout << route_table[i].ttl << " ";
	}
	cout << endl;
}

/* Create an RIPPacket. Command dictates whether packet sent is a request or response. */
RIPPacket *create_rip_packet(uint16_t command, uint32_t send_ip) {

	RIPPacket *packet = new RIPPacket(command);
	if (command == 1) {
		return packet;
	}

	for (unsigned int i = 0; i < route_table.size(); i++) {
		if (route_table[i].next_hop == send_ip) {
			packet->addEntry(route_table[i].dest, INFINITY);
		}
		else {
			packet->addEntry(route_table[i].dest, route_table[i].cost);
		}
	}
	return packet;
}

/* Print contents of an RIP packet (debugging) */
void print_rip_packet(RIPPacket * packet) {

	cout << packet->command << endl;
	cout << packet->num_entries << endl;
	for (unsigned int i = 0; i < packet->num_entries; i++) {
		cout << cast_ntoa(packet->entries[i].address) << " " << packet->entries[i].cost << endl;
	}
	cout << endl;

}

/* Processes either an RIP packet request or a response. */
void handle_rip_packet(RIPPacket * packet, uint32_t ip)
{
	uint16_t command = packet->command;
	uint32_t next_ip = my_ip_to_other(ip);

	if (next_ip == 0)
		return;

	if (command == 1) {
		RIPPacket * rip = create_rip_packet(2, next_ip);
		char * payload_rip = (char*) malloc(MTU);
		serialize(rip, payload_rip);
		package_and_send(payload_rip, 200, next_ip, (uint32_t) INFINITY, false);
		free(payload_rip);
		delete rip;
	}
	else if (command == 2) {
		update_routes(packet, next_ip);
	}

}

/* Send RIP requests across all available interfaces. */
void send_requests_all()
{
	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		interface ifc = my_interfaces[i];
		if (ifc.status == "up") {
			RIPPacket * rip = create_rip_packet(1, ifc.other_vip);
			char * payload_rip = (char *) malloc(MTU);
			serialize(rip, payload_rip);
			package_and_send(payload_rip, 200, ifc.other_vip, (uint32_t) INFINITY, false);
			free(payload_rip);
			delete rip;
		}
	}
}

/*	
	When route table information changes, triggered updates immediately sends changes
	to all interfaces in the form of an RIP response packet.
*/
void triggered_updates()
{
	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		interface ifc = my_interfaces[i];
		if (ifc.status == "up") {
			RIPPacket * rip = create_rip_packet(2, ifc.other_vip);
			char * payload_rip = (char *) malloc(MTU);
			serialize(rip, payload_rip);
			package_and_send(payload_rip, 200, ifc.other_vip, (uint32_t) INFINITY, false);
			free(payload_rip);
			delete rip;
		}
	}
}

/* Prints information used for a single route (debugging). */
void print_route(route *r)
{
	cout << "Destination: " << cast_ntoa(r->dest) << " ";
	cout << "Next hop: " << cast_ntoa(r->next_hop) << " ";
	cout << "Cost: " << r->cost << " ";
	cout << "TTL: " << r->ttl << endl;
}

/* Called when route information is received via periodic updates. Route table updated. */
void update_routes(RIPPacket * rip, uint32_t other_ip) {

	bool changed = false;
	for (int i = 0; i < rip->num_entries; i++) {
		changed = changed || merge_routes(rip->entries[i].address, rip->entries[i].cost, other_ip);
	}
	if (changed) {
		triggered_updates();
	}

}

/* Resolves route table to contain up to date information about available routes. */
bool merge_routes(uint32_t dest, uint32_t cost, uint32_t other_ip) {

	for (uint32_t i = 0; i < route_table.size(); i++) {
		if (dest == route_table[i].dest) {
			if (cost + 1 < route_table[i].cost) {
				route_table[i].ttl = MAX_TTL;
				route_table[i].next_hop = other_ip;
				route_table[i].cost = cost + 1;
				return true;
			}
			else if (other_ip == route_table[i].next_hop) {
				route_table[i].ttl = MAX_TTL;
				if (route_table[i].cost == INFINITY && cost == INFINITY) {
					return false;
				}
				if (cost == INFINITY) {
					route_table[i].cost = INFINITY;
					return true;
				}
				if (cost + 1 == route_table[i].cost) {
					return false;
				}
				if (cost + 1 < route_table[i].cost) {
					route_table[i].cost = cost + 1;
					return true;
				}
			}
			return false;
		}
	}

	route r;
	r.dest = dest;
	r.ttl = MAX_TTL;
	r.next_hop = other_ip;
	r.cost = cost + 1;
	route_table.push_back(r);
	return true;
}

/* Parses text file detailing interface details. */
void read_text(char *text) {

	string line;
	string ip;
	string delim = ":";
	int i = 1;
	size_t index;
	ifstream myfile(text);

	if (myfile.is_open()) {

		myfile >> line;
		index = line.find(delim);

		ip = line.substr(0, index);
		if (ip == "localhost") {
			my_ip_addr.sin_addr.s_addr = htonl(cast_aton(localhost));
		}
		else {
			my_ip_addr.sin_addr.s_addr = htonl(cast_aton((char *) ip.c_str()));
		}

		line = line.substr(index + 1);

		my_ip_addr.sin_family = AF_INET;
		my_ip_addr.sin_port = htons((uint16_t) atoi(line.c_str()));

		while (!myfile.eof())
		{
			interface ifc;

			ifc.num = i;

			myfile >> line;
			index = line.find(delim);

			ip = line.substr(0, index);
			if (ip == "localhost") {
				ifc.addr.sin_addr.s_addr = htonl(cast_aton(localhost));
			}
			else
				ifc.addr.sin_addr.s_addr = htonl(cast_aton((char *) ip.c_str()));

			ifc.addr.sin_family = AF_INET;

			line = line.substr(index + 1);
			ifc.addr.sin_port = htons((uint16_t) atoi(line.c_str()));

			myfile >> line;
			ifc.my_vip  = cast_aton((char *) line.c_str());

			myfile >> line;
			ifc.other_vip = cast_aton((char *) line.c_str());

			ifc.status = "up";

			my_interfaces.push_back(ifc);
			i++;
		}

		myfile.close();

		for (unsigned int i = 0; i < my_interfaces.size(); i++) {
			route r;
			r.dest = my_interfaces[i].my_vip;
			r.next_hop = my_interfaces[i].my_vip;
			r.cost = 0;
			r.ttl = MAX_TTL;
			route_table.push_back(r);
		}

		for (unsigned int i = 0; i < my_interfaces.size(); i++) {
			route r;
			r.dest = my_interfaces[i].other_vip;
			r.next_hop = my_interfaces[i].other_vip;
			r.cost = 1;
			r.ttl = MAX_TTL;
			route_table.push_back(r);
		}
	}

	else
		cout << "File does not exist." << endl;

	return;
}

/* For an IP address on local interface, returns remote IP address. */
uint32_t my_ip_to_other(uint32_t my_ip) {

	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		if (my_interfaces[i].my_vip == my_ip) {
			return my_interfaces[i].other_vip;
		}
	}
	return 0;
}

/* For a given remote IP address, returns IP address of local interface. */
uint32_t other_ip_to_my(uint32_t my_ip) {

	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		if (my_interfaces[i].other_vip == my_ip) {
			return my_interfaces[i].my_vip;
		}
	}
	return 0;
}

/* Returns the appropriate interface corresponding to a route. */
interface *route_to_interface(route *r) {

	uint32_t next_hop = r->next_hop;
	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		if (my_interfaces[i].other_vip == next_hop) {
			return &my_interfaces[i];
		}
	}
	return NULL;
}

/* Returns the interface number corresponding to a remote vitual IP address. */
uint32_t vip_to_interface(uint32_t ip) {

	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		if (my_interfaces[i].other_vip == ip) {
			return my_interfaces[i].num;
		}
	}
	return 0;
}

/* Determines whether a virtual IP address corresponds to an interface. */
bool destination_is_interface(uint32_t ip) {
	for (unsigned int i = 0; i < my_interfaces.size(); i++) {
		if (my_interfaces[i].my_vip == ip) {
			return true;
		}
	}
	return false;
}

/* Converts addresses from network byte order to dotted string. */
string cast_ntoa(uint32_t n) {
	struct in_addr address;
	address.s_addr = n;
	char * ch = inet_ntoa(address);
	string str = (string) ch;
	return str;
}

/* Converts dotted notation string to network byte order address. */
uint32_t cast_aton(char *a) {
	return inet_addr(a);
}