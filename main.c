/**
 * A benchmark for dpdk rx capacity.
 *
 * Intended for use with DPDK ostinato or similar generating line rate 64byte packets.
 *
 * The benchmark then attempts to capture in memory and count as many packets as possible.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <unistd.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>


#include "main.h"
#include <signal.h>
#include <getopt.h>

static volatile int stop = 0;

// Define the function to be called when ctrl-c (SIGINT) signal is sent to process
static void signal_callback_handler (int signum) {
	// This way we use signum
	stop = 1 | signum;
}

static void print_stats (void);
static void print_stats (void) {
	struct rte_eth_stats eth0_stats = {0};
	rte_eth_stats_get(0, &eth0_stats);
	printf("Success rx pkt = %"PRIu64
	       "\nSuccess rx byt = %"PRIu64
	       "\nErroneous rx pkt = %"PRIu64
	       "\nmulticast rx pkt = %"PRIu64
	       "\nRX mbuf fail = %"PRIu64
	       "\nmatch filter pkts = %"PRIu64
	       "\n!match filter pkts = %"PRIu64
	       "\nqueue RX pkts = %"PRIu64
	       "\nqueue RX bytes = %"PRIu64
	       "\nqueue RX errors(i.e. dropped) = %"PRIu64"\n",
	       eth0_stats.ipackets,
	       eth0_stats.ibytes,
	       eth0_stats.ierrors,
	       eth0_stats.imcasts,
	       eth0_stats.rx_nombuf,
	       eth0_stats.fdirmatch,
	       eth0_stats.fdirmiss,
	       eth0_stats.q_ipackets[0],
	       eth0_stats.q_ibytes[0],
	       eth0_stats.q_errors[0]);

}


static double ts_to_double(struct timespec ts) {
	return ts.tv_sec + ((double)ts.tv_nsec / 10e9);
}

/**
 * We can simulate load here per packet here.
 */
static void per_packet (struct rte_mbuf* pkt) {
	pkt->pkt.pkt_len += ETHER_CRC_LEN;
	pkt->pkt.data_len += ETHER_CRC_LEN;
	/* YES this looks like a terrible idea, but kernels and
	 * linux has evolved alot on a new Linux kernel (post 2011) this is OK
	 * to do. See vsyscall/VDIO's
	 */
	// clock_gettime(CLOCK_REALTIME, &end);
}


uint64_t queue_nb_packets[RTE_MAX_LCORE] = {0};
double queue_pps[RTE_MAX_LCORE] = {0};
double queue_time[RTE_MAX_LCORE] = {0};

struct configuration {
	size_t burst_size; // The size burst size we read packet from DPDK with
	int bad_numa; // purposely miss configure memory to see performance hit
	int per_node_mempool; // use a mempool for each CPU node as opposed to a single mempool
	unsigned int timeout; // stop the test after X seconds, set 0 for no timeout
	unsigned mbuf_size; // The size of a mbuf the largest packet we can accept (we add dpdk header ontop of this)
	unsigned rx_queue_size; // The number of mbuf for every rx queue (MAX 4K limited by DPDK)
	unsigned cache_size; // The size of the mempool per lcore cache
	const char *output; // The output file
	const char *c; // The CPU mask used
	const char *n; // The number of memory channels used
};

static struct configuration config = {
	.burst_size = 10,
	.bad_numa = 0,
	.per_node_mempool = 0,
	.timeout = 0,
	.mbuf_size = 1518,
	.rx_queue_size = 4096,
	.cache_size = 8,
	.output = "output.csv"
};


/**
 * @brief Reads packets as fast as possible
 * @param The RSS queue id as a (as a uint16_t)
 * @return
 */
static int lcore_benchmark(void *arg)
{
	struct rte_mbuf* pkts_burst[config.burst_size]; // Batch of packet membuf
	uint16_t nb_rx; // Number of rx packets we've recevied in a batch read
	uint64_t tot_nb_pkt = 0; // Total number of packets seen
	uint16_t queue = (int)(intptr_t) arg; // The argument we are passed is our (RSS) queue

	struct timespec start, end;

	printf("Hello from core %u queue %d\n", rte_lcore_id(), queue);
	clock_gettime(CLOCK_REALTIME, &start);

	while (!stop) {
		/* Get a burst of size one from port 0 into buffer 1 */
		nb_rx = rte_eth_rx_burst((uint8_t) 0, queue, pkts_burst, config.burst_size);
		if (nb_rx > 0) {
			int i;
			for (i = 0; i < nb_rx; ++i) {
				per_packet(pkts_burst[i]);
				rte_pktmbuf_free(pkts_burst[i]);
			}
			tot_nb_pkt+=nb_rx;
		}
	}
	clock_gettime(CLOCK_REALTIME, &end);

	printf("Exiting lcore %u - received %"PRIu64" packets\n", rte_lcore_id(), tot_nb_pkt);
	queue_nb_packets[rte_lcore_id()] = tot_nb_pkt;
	print_stats();

	queue_time[rte_lcore_id()] = ts_to_double(end) - ts_to_double(start);
	queue_pps[rte_lcore_id()] = queue_nb_packets[rte_lcore_id()] / queue_time[rte_lcore_id()];
	printf("Thread #%d(%d) packets %"PRIu64" in %fsec so %f pp/s\n", queue, rte_lcore_id(), queue_nb_packets[rte_lcore_id()], queue_time[rte_lcore_id()], queue_pps[rte_lcore_id()]);
	return 0;
}

/* Can set jumbo frames/ or limit the size of a frame by setting both
 * max_rx_pkt_len and jumbo_frame. This can be limited to less than
 * the max ethernet packet size.
 */
static const struct rte_eth_conf port_conf = {
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IPV4_UDP | ETH_RSS_IPV6 | ETH_RSS_IPV4 | ETH_RSS_IPV4_TCP | ETH_RSS_IPV6_TCP | ETH_RSS_IPV6_UDP,
		}
	},
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS ,
		.max_rx_pkt_len = 0,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_DCB_NONE,
	},
};

static struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 8,//RX_PTHRESH,
		.hthresh = 8,//RX_HTHRESH,
		.wthresh = 4,//RX_WTHRESH,
	},
	.rx_drop_en = 0,
	.rx_free_thresh = 0,
	/* .start_rx_per_q = 0 // seems new in 1.7 if true we can stop and start queues independantly */
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 36,//TX_PTHRESH,
		.hthresh = 0,//TX_HTHRESH,
		.wthresh = 4,//TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 1, /* Use PMD default values */
};

static void print_usage(void){
	fprintf(stderr, "./dpdk_benchmark -c -n [DPDK OPTIONS] -- [BENCHMARK OPTIONS]\n"
		"DPDK OPTIONS\n"
		"\t-c (required) hexidecimal cpu mask -c1 use core 1, -ca use core 2 and 4.\n"
		"\t-n (required) the number of memory channels typically #ram/2 if all slots are full.\n"
		"\t-w (optional) Whitelist a single pci device port (we require there to only be one)\n"
		"BENCHMARK OPTIONS\n"
		"--burst-size,-b\n"
		"--bad-numa,-n Makes sure memory is mapped incorrectly on NUMA systems\n"
		"--per-node-mempool,-p\n"
		"--timeout,-t Stop test after X seconds\n"
		"--mbuf-size,-m The largest packet you want to capture (bytes)\n"
		"--rx-queue-size,-r\n"
		"--cache-size,-c The mempool TLS cache size\n"
		"--output,-o Output csv file to record results (default output.csv)\n"
		"--pthresh,-P\n"
		"--hthresh,-H\n"
		"--wthresh,-W\n"
		"--rx_drop_en,-D\n"
		"--rx_free_thresh,-F\n"
		"--help,-h,-?\n"
		);

	fprintf(stderr, "DPDK OPTIONS");
}


static void parse_args(int argc, char **argv) {
	int c;

	static struct option long_options[] =
	{
		/* These options set a flag. */
		{"burst-size", required_argument, 0, 'b'},
		{"bad-numa", optional_argument, 0, 'n'},
		{"per-node-mempool", optional_argument, 0, 'p'},
		{"timeout", required_argument, 0, 't'},
		{"mbuf-size", required_argument, 0, 'm'},
		{"rx-queue-size", required_argument, 0, 'r'},
		{"cache-size", required_argument, 0, 'c'},
		{"output", required_argument, 0, 'o'},
		{"pthresh", required_argument, 0, 'P'},
		{"hthresh", required_argument, 0, 'H'},
		{"wthresh", required_argument, 0, 'W'},
		{"rx_drop_en", optional_argument, 0, 'D'},
		{"rx_free_thresh", required_argument, 0, 'F'},
		{"help", required_argument, 0, '?'},
		{0, 0, 0, 0}
	};

	while(1) {
		int option_index = 0;
		c = getopt_long (argc, argv, "b:n::p::t:m:r:co:P:W:H:D::F:h?",
				       long_options, &option_index);
		if (c==-1)
			break;
		switch (c) {
		case 'b':
			config.burst_size = atoi(optarg);
			break;
		case 'n':
			if (optarg) {
				config.bad_numa = atoi(optarg);
			} else {
				config.bad_numa = 1;
			}
			break;
		case 'p':
			if (optarg) {
				config.per_node_mempool = atoi(optarg);
			} else {
				config.per_node_mempool = 1;
			}
			break;
		case 't':
			config.timeout = atoi(optarg);
			break;
		case 'm':
			config.mbuf_size = atoi(optarg);
			break;
		case 'r':
			config.rx_queue_size = atoi(optarg);
			break;
		case 'c':
			config.cache_size = atoi(optarg);
			break;
		case 'o':
			config.output = optarg;
			break;
		case 'P':
			rx_conf.rx_thresh.pthresh = atoi(optarg);
			break;
		case 'H':
			rx_conf.rx_thresh.hthresh = atoi(optarg);
			break;
		case 'W':
			rx_conf.rx_thresh.wthresh = atoi(optarg);
			break;
		case 'D':
			if (optarg) {
				rx_conf.rx_drop_en = atoi(optarg);
			} else {
				rx_conf.rx_drop_en = 1;
			}
			break;
		case 'F':
			rx_conf.rx_free_thresh = atoi(optarg);
			break;
		default:
		case'?':
		case 'h':
			print_usage();
			exit(0);
		}
	}
}

static int file_exists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
	fclose(file);
	return 1;
    }
    return 0;
}

static void write_output(void) {
	FILE *file;
	struct rte_eth_stats eth0_stats = {0};
	rte_eth_stats_get(0, &eth0_stats);

	printf("Read = %"PRIu64
	       "\nDropped = %"PRIu64
	       "\nRatio = %f\n",
	       eth0_stats.ipackets,
	       eth0_stats.ierrors,
	       (double) eth0_stats.ipackets / (eth0_stats.ipackets + eth0_stats.ierrors));

	if (!file_exists(config.output)) {
		if ((file = fopen(config.output, "w"))) {
			fprintf(file, "capture_rate,accepted,dropped,runtime,burst_size,bad_numa,per_node_mempool,timeout,mbuf_size,"
				"rx_queue_size,cache_size,pthresh,hthresh,wthresh,rx_drop_en,rx_free_thresh,-c,-n\n");
		}
	} else {
		file = fopen(config.output, "a");
	}
	if (file) {
		fprintf(file, "%f,%"PRIu64",%"PRIu64",%f,%zu,%d,%d,%u,%u,"
			"%u,%u,%"PRIu8",%"PRIu8",%"PRIu8",%"PRIu8",%"PRIu16",%s,%s\n",
			(double) eth0_stats.ipackets / (eth0_stats.ipackets + eth0_stats.ierrors),
			eth0_stats.ipackets,
			eth0_stats.ierrors,
			queue_time[rte_get_master_lcore()],
			config.burst_size,
			config.bad_numa,
			config.per_node_mempool,
			config.timeout,
			config.mbuf_size,
			config.rx_queue_size,
			config.cache_size,
			rx_conf.rx_thresh.pthresh,
			rx_conf.rx_thresh.hthresh,
			rx_conf.rx_thresh.wthresh,
			rx_conf.rx_drop_en,
			rx_conf.rx_free_thresh,
			config.c,
			config.n
			);
		fclose(file);
	}

}


int
MAIN(int argc, char **argv)
{
	int ret, i;
	struct rte_eth_dev_info dev_info; /* Confirm our device setup */
	struct rte_config * global_config; /* Confirm our setup */
	int nb_workers;
	unsigned lcore_id;
	unsigned nb_numa_nodes = 1;
	struct rte_mempool * pktmbuf_pool[RTE_MAX_NUMA_NODES] = {NULL};
	unsigned ports_per_numa[RTE_MAX_NUMA_NODES] = {0};

	/* Register signal and signal handler */
	signal(SIGINT, signal_callback_handler);
	signal(SIGALRM, signal_callback_handler);

	/* Grab -n and -c as we want to print them out
	 * DPDK init eal will fail without these correctly specified
	 * hence the lack of error checking */
	for (i = 1; i < argc; ++i) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == 'c' && !config.c) {
				if (argv[i][2] == 0)
					config.c = argv[i+1];
				else
					config.c = &argv[i][2];
			} else if (argv[i][1] == 'n' && !config.n) {
				if (argv[i][2] == 0)
					config.n = argv[i+1];
				else
					config.n = &argv[i][2];
			}
		}

	}

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	/* Our args are here at the end :) */
	if (argc-ret > 1)
		parse_args(argc-ret, argv+ret);

	rte_set_log_level(RTE_LOG_DEBUG);
	global_config = rte_eal_get_configuration();
	nb_workers = rte_lcore_count();

	if (global_config != NULL) {
		printf("Intel DPDK setup\n"
		       "---Master LCore : %"PRIu32"\n"
		       "---LCore Count  : %"PRIu32"\n",
		       global_config->master_lcore, global_config->lcore_count);

		for (i = 0 ; i < sysconf(_SC_NPROCESSORS_ONLN) ; ++i) {
			printf("   ---Core %d : %s (NUMA=%d)\n", i,
			       global_config->lcore_role[i] == ROLE_RTE ? "on" : "off", rte_lcore_to_socket_id(i));
			nb_numa_nodes = MAX(nb_numa_nodes, rte_lcore_to_socket_id(i)+1);
		}

		const char * proc_type;
		switch (global_config->process_type) {
		case RTE_PROC_AUTO:
			proc_type = "auto";
			break;
		case RTE_PROC_PRIMARY:
			proc_type = "primary";
			break;
		case RTE_PROC_SECONDARY:
			proc_type = "secondary";
			break;
		case RTE_PROC_INVALID:
			proc_type = "invalid";
			break;
		default:
			proc_type = "something worse than invalid!!";
		}
		printf("---Process Type : %s\n", proc_type);
	}

	/* Make sure bad_numa is either 0 or 1
	 * We use this as a offset to to make a bad numa setup
	 */
	config.bad_numa = !!config.bad_numa;
#define NUMA_NODE(i) ((rte_lcore_to_socket_id(i)+config.bad_numa)%nb_numa_nodes)

	/* Figure out how many cores we have per NUMA node with any bad numa setup taken into account */
	RTE_LCORE_FOREACH(lcore_id) {
		unsigned node = NUMA_NODE(lcore_id);
		if (node >= nb_numa_nodes)
			rte_exit(EXIT_FAILURE, "Invalid NUMA node %u (maybe you need to increase RTE_MAX_NUMA_NODES) \n", node);
		else
			++ports_per_numa[node];
	}

	/* Add DPDK overheads onto the packet size */
	printf("MBUF size is (%u + sizeof(rte_mbuf):%zu + HEADROOM:%d)\n", config.mbuf_size, sizeof(struct rte_mbuf), RTE_PKTMBUF_HEADROOM);
	config.mbuf_size += sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;

	/* We are reserving memory make sure we account for TLS caches and the number of workers
	 * Also include some extra leeway, if we see a low packet count this is the issue!!
	 */
	if (config.per_node_mempool) {
		/* Make a pool per numa node */
		char mempoolname[] = "Xmbuf_pool";
		for (i = 0; (unsigned) i < nb_numa_nodes; ++i) {
			if (!ports_per_numa[i])
				continue;
			mempoolname[0] = '0'+i;
			fprintf(stderr, "Creating mempool %d with %d elements\n", i, (config.rx_queue_size+config.cache_size) * ports_per_numa[i]);
			pktmbuf_pool[i] = rte_mempool_create(mempoolname, (config.rx_queue_size+config.cache_size) * ports_per_numa[i] + 100,
							     config.mbuf_size, config.cache_size,
							     sizeof(struct rte_pktmbuf_pool_private),
							     rte_pktmbuf_pool_init, NULL,
							     rte_pktmbuf_init, NULL,
							     i, 0);
			if (pktmbuf_pool[i] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool #%d\n", i);
		}

	} else {
		fprintf(stderr, "Creating mempool with %d elements\n", (config.rx_queue_size+config.cache_size) * nb_workers + 100);
		/* Share a single pool, I think SOCKET_ID_ANY gets converted to current thread anyway */
		pktmbuf_pool[0] = rte_mempool_create("mbuf_pool", (config.rx_queue_size+config.cache_size) * nb_workers + 100,
						     config.mbuf_size, config.cache_size,
						     sizeof(struct rte_pktmbuf_pool_private),
						     rte_pktmbuf_pool_init, NULL,
						     rte_pktmbuf_init, NULL,
						     SOCKET_ID_ANY, 0);
		if (pktmbuf_pool[0] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init single mbuf pool\n");
		for (i = 1; (unsigned) i < nb_numa_nodes; ++i) {
			pktmbuf_pool[i] = pktmbuf_pool[0];
		}
	}

	//rte_mempool_dump (stdout, pktmbuf_pool[0]);

	/* This appears to loop through all of the drivers and
	 * binds them to any non-blacklisted PCI device that the
	 * driver supports
	 */
	if (rte_eal_pci_probe() < 0)
		rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");

	if (rte_eth_dev_count() != 1) {
		fprintf(stderr, "rte_eth_dev_count %d\n", rte_eth_dev_count());
		rte_exit(EXIT_FAILURE, "Expects only one dpdk port (use -w to whitelist a single port)\n");
	}

	// This must be called first before another *eth* function -
	// init the device and queues (Stuff such as checksum offloading etc can be done here)
	// 1 rx, 1 tx queue for device XXX
	printf("rte_eth_dev_config starting rx %d tx 1\n", nb_workers);
	ret = rte_eth_dev_configure((uint8_t) 0, nb_workers, 1, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
			 ret, 0);

	// init TX queue - must be done no matter what TX_QUEUE cannot be set to 0
	ret = rte_eth_tx_queue_setup((uint8_t) 0, 0, 64,
				     SOCKET_ID_ANY, &tx_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
			 ret, 0);

	// init RX queue
	i = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		printf ("Configuring queue %d\n", i);
		ret = rte_eth_rx_queue_setup((uint8_t) 0, i, config.rx_queue_size, NUMA_NODE(lcore_id), &rx_conf, pktmbuf_pool[NUMA_NODE(lcore_id)]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u EINVAL=%d ENOMEM=%d\n",
				 ret, 0, EINVAL, ENOMEM);
		//printf("rte_mempool_count %d\n", (int) rte_mempool_count(pktmbuf_pool));
		//printf("rte_mempool_free_count %d\n", (int) rte_mempool_free_count(pktmbuf_pool));
		i++;
	}

	/* Start device */
	ret = rte_eth_dev_start((uint8_t) 0);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
			 ret, 0);

	rte_eth_dev_info_get((uint8_t) 0, &dev_info);
	printf("Got Device info for port %"PRIu8":\n"
	       "---driver        : %s\n"
	       "---rx_bufsize    : %"PRIu32"\n"
	       "---max_rx_pktlen : %"PRIu32"\n"
	       "---max_rx_queues : %"PRIu16"\n"
	       "---max_tx_pktlen : %"PRIu16"\n"
	       "---max_mac_addrs : %"PRIu32"\n",
	       (uint8_t) 0, dev_info.driver_name,
	       dev_info.min_rx_bufsize, dev_info.max_rx_pktlen,
	       dev_info.max_rx_queues, dev_info.max_tx_queues,
	       dev_info.max_mac_addrs);

	/* Set interface promiscuous */
	rte_eth_promiscuous_enable((uint8_t) 0);
	printf("Device %u : Promiscuous %u (after)\n", (unsigned int) 0 , rte_eth_promiscuous_get((uint8_t) 0));

	// map queue 0 to 0 , doesn't appear to be hooked up ENOTSUP
	// igxbe driver looks like it has this
	//ret = rte_eth_dev_set_rx_queue_stats_mapping(0, 0, 0);
	if ( ret != 0 )
		printf("Failed to rte_eth_dev_set_rx_queue_stats_mapping with error: %d %s %d\n", ret, strerror(ret), -ENOTSUP);

	/* Wait for link to come up */
	struct rte_eth_link link_info;
	rte_eth_link_get(0, &link_info);

	/* Set alarm we have started the capture now */
	if (config.timeout)
		alarm(config.timeout);

	intptr_t master = 0;
	i = 0;
	lcore_id = 0;
	/* call lcore_benchmark() on every slave lcore */
	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id != rte_get_master_lcore()) {
			printf("Remote launch %d\n", i);
			rte_eal_remote_launch(lcore_benchmark, (void *)(intptr_t) i, lcore_id);
		} else {
			master = i;
		}
		++i;
	}

	/* call it on master lcore too */
	lcore_benchmark((void *)master);

	rte_eal_mp_wait_lcore();

	write_output();
	return 0;
}
