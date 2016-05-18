#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pthread.h>
#include <unistd.h>
#define NUM_BUCKETS 100
#define THRESHOLD 1000	/*in BYTES*/
#define DSCP 192		/*192 = 11000000 in BIN (8 type of service bits)*/
#define TCP 6
#define UDP 17

//IPV4 header structure RFC791 ref.
struct ipv4hdr{
	uint8_t version_ihl;
	uint8_t type_of_service;
	uint16_t len;
	uint16_t id;
	uint16_t flags_frags;
	uint8_t live_time;
	uint8_t hw_proto;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t options_padding;
};

//TCP header structure
struct tcphdr{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t off_res_con;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
	uint32_t options_padding;
};

//KEY struct used to identify a flow
typedef struct  key{
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  hw_proto;
}key;

//Node struct for each node in the linked list associated with the hashed table entries
typedef struct node{
	key key;
	int packetSizeCounter;
	int isQOSSet;
	struct node *next;
}node;

//Bucket strcut having a pointer to linked list
typedef struct bucket{
	struct node *listStart;
}bucket;

//s1 struct with mutex and bucket ptr
typedef struct s1{
	pthread_mutex_t m1;
	bucket* b;
}s1;

static bucket *buckets; //global array of buckets
s1 mutex; //Global structure having a mutex and buckets pointer

//! \brief Match two keys. Keys structure defined as above
//! \param key1
//! \param key2
//! \return Boolean value for succcess failure
int keysMatch(key key1, key key2){
	if (key1.src_ip == key2.src_ip &&
		key1.src_port == key2.src_port &&
		key1.dst_ip == key2.dst_ip &&
		key1.dst_port == key2.dst_port &&
		key1.hw_proto == key2.hw_proto) return 1;
	else return 0;
}

//! \brief Delete a particular list of a bucket
//! \param list header pointer to pointer
//! \return nothing
void deleteList(node **head){
	if (head != NULL){
		node *current = *head;
		node *next;
		while(current){
			next = current->next;
			free(current);
			current = next;
		}
		*head = NULL;
	}
}

//! \brief Flush all the buckets
//! \param buckets
//! \return buckets which are now empty
//! \note Should be called using a seperate thread. <TODO>
bucket* flushTable(bucket* buckets){
	int i = 0;
	for (i = 0; i < NUM_BUCKETS; ++i){
		deleteList(&buckets[i].listStart);
	}
	return buckets;
}

//not used.
void printTable(bucket* buckets){
	int i = 0;
	node *temp;
	for (i = 1; i < NUM_BUCKETS; ++i){
		if(buckets[i].listStart != NULL) printf("Index %d\n", i);
		else continue;
		temp = buckets[i].listStart;
		while(temp){
			printf("%u,%u->%u,%u|proto:%u,QOS:%d,packetSizeCounter:%d\n", temp->key.src_ip, temp->key.src_port, temp->key.dst_ip,
				temp->key.dst_port, temp->key.hw_proto, temp->isQOSSet, temp->packetSizeCounter);
			temp = temp->next;
		}
	}
}

//! \brief Entry point for flushing hashTable
//! \param args
//! \return void*
void* flushthread(void* args){
	s1* s = (s1*)args;
	bucket* b;
	while(1){
		//printTable(buckets);
		pthread_mutex_lock (&(s->m1));
		b = (bucket*) (s->b);
		buckets = flushTable(b);
		pthread_mutex_unlock (&(s->m1));
		sleep(60);
	}
}

//! \brief Multi-use function to search insert or update entries in the hashed table
//! \param buckets
//! \param index obtained using hasing function
//! \param failed indicates whether any of the three operation has failed (0 is success)
//! \param key key identifies the flow
//! \param packetSizeCounter gets incremented at every new flow
//! \param retPacket all the 3 operations(search, insert, update) return the pointer to the particular node
//! \return buckets
bucket* srchInsUpd(bucket *buckets, int index, int *failed, key key, int packetSizeCounter, node **retPacket){
	if (buckets[index].listStart == NULL){
		//For the first entry
		buckets[index].listStart = (node *)malloc(sizeof(node));
		buckets[index].listStart->key = key;
		buckets[index].listStart->packetSizeCounter = packetSizeCounter;
		buckets[index].listStart->isQOSSet = 0;
		buckets[index].listStart->next = NULL;
		*failed = 0;
		*retPacket = buckets[index].listStart;
		return buckets;
	} 

	node *temp = buckets[index].listStart;
	node *prev = temp;
	while(temp){
		if (keysMatch(temp->key, key)){
			//update counter
			temp->packetSizeCounter += packetSizeCounter;
			*failed = 0;
			*retPacket = temp;
			break;
		}
		else *failed = 1;
		prev = temp;
		temp = temp->next;
	}
	// If search fails, insert a new node at the end
	if (*failed){
		node *newNode;
		newNode = (node *)malloc(sizeof(node));
		newNode->key = key;
		newNode->packetSizeCounter = packetSizeCounter;
		newNode->isQOSSet = 0;
		newNode->next = NULL;
		prev->next = newNode;
		*failed = 0;
		*retPacket = newNode;
	}
	return buckets;
}

//! \brief Get index after hashing on the packet Key
//! \param Key
//! \return index obtained after hashing
//! \note Use a better hashing function <TODO>
int hashIndex(key key){
	return (key.src_ip + key.src_port + key.dst_ip + key.dst_port + key.hw_proto) % NUM_BUCKETS;
}

//! \brief Calculate the IP header checksum. (Taken from RFC791)
//! \param buf The IP header content.
//! \param hdr_len The IP header length.
//! \return The result of the checksum.
uint16_t ip_checksum(const void *buf, size_t hdr_len){
	unsigned long sum = 0;
	const uint16_t *ip1;
	ip1 = buf;
	while (hdr_len > 1){
	 sum += *ip1++;
	 if (sum & 0x80000000)
	         sum = (sum & 0xFFFF) + (sum >> 16);
	 hdr_len -= 2;
	}

	while (sum >> 16)
	     sum = (sum & 0xFFFF) + (sum >> 16);
	return(~sum);
}

//! \brief Callback function which is invoked for each packet out.
//! \param qh Queue handler
//! \param nfmsg Used for getting packet header
//! \param nfa 
//! \param data 
//! \return The result of set verdict function of NFQ library.
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data){
	unsigned char *foo;
	size_t ret1 = 0;
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int threshold = THRESHOLD;
	int failed = 0;
	node *retPacket = NULL;
	struct ipv4hdr *ipv4hdr;
	struct tcphdr *tcphdr;
	size_t hdr_len = 0;
	uint8_t mask = 0x0f;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	
	ret1 = nfq_get_payload(nfa, &foo);
	ipv4hdr = (struct ipv4hdr *)foo;
	hdr_len = (mask & ipv4hdr->version_ihl)*4;
	tcphdr = (struct tcphdr *)(ipv4hdr + hdr_len);
	key key = {ipv4hdr->src_ip, ipv4hdr->dst_ip, tcphdr->src_port, tcphdr->dst_port, ipv4hdr->hw_proto};	

	/*Locking Buckets before reading or writing*/
	
	if (key.src_ip != key.dst_ip 
		&& (key.hw_proto == TCP || key.hw_proto == UDP)){
		pthread_mutex_lock (&(mutex.m1));
		int index = hashIndex(key);
		buckets = srchInsUpd(buckets, index, &failed, key, ret1, &retPacket);
		pthread_mutex_unlock (&(mutex.m1));
	}
	else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);	
	}
	

	/*Important conditions to be met before setting the QOS field are:
	1. Packetsize exceeeds threshold
	2. QOS bits are not set already. If they are, we assume that controller has already installed new path.
	3. Protocol type of the IP header can be TCP,UDP only. Ignore others
	*/
	if (retPacket != NULL
		&& retPacket->packetSizeCounter > threshold 
		&& !failed 
		&& !retPacket->isQOSSet){
		pthread_mutex_lock (&(mutex.m1));
		retPacket->isQOSSet = 1;
		pthread_mutex_unlock (&(mutex.m1));
		ipv4hdr->type_of_service = DSCP;
		ipv4hdr->checksum = 0;//important to set checksum to 0 before recalculating
		foo = (unsigned char *)ipv4hdr;
		ipv4hdr->checksum = ip_checksum(foo, hdr_len);
		foo = (unsigned char *)ipv4hdr;
		return nfq_set_verdict(qh, id, NF_ACCEPT, ret1, foo);
	}
	else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);	
	}
}

int main(int argc, char **argv){
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));
	buckets = (bucket *)malloc(sizeof(bucket) * NUM_BUCKETS);

	pthread_t timerThread;
	void *ret;
	mutex.b = buckets;
	timerThread = pthread_create(&timerThread, NULL, flushthread, &mutex);

	if (argc == 2) {
		queue = atoi(argv[1]);
		if (queue > 65535) {
			fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

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

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {

		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
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

	pthread_join(timerThread, &ret);
	printf("Thread finished with return code %p\n", ret);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
