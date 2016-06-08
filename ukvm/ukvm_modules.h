#ifndef __UKVM_MODULES_H__
#define __UKVM_MODULES_H__

struct ukvm_module {
    int (*handle_exit)(struct kvm_run *run, uint8_t *mem);
    int (*setup_module)(char *cmdarg);
};

extern struct ukvm module ukvm_disk;

/* ukvm_disk.c */
#define UKVM_PORT_BLKINFO   0x502
#define UKVM_PORT_BLKWRITE  0x503
#define UKVM_PORT_BLKREAD   0x504

#define UKVM_PORT_NETINFO   0x505
#define UKVM_PORT_NETWRITE  0x506
#define UKVM_PORT_NETREAD   0x507

#define UKVM_PORT_DBG_STACK 0x508

#define UKVM_PORT_GETVAL    0x509
#define UKVM_PORT_PUTVAL    0x50a

/* UKVM_PORT_GETVAL */
struct ukvm_getval {
	/* OUT */
	uint64_t value;
};

/* UKVM_PORT_PUTVAL */
struct ukvm_putval {
	/* IN */
	uint64_t value;
};

/* UKVM_PORT_PUTS */
struct ukvm_puts {
	/* IN */
	char *data;
	int len;
};

/* UKVM_PORT_NANOSLEEP */
struct ukvm_nanosleep {
	/* IN */
	uint64_t sec_in;
	uint64_t nsec_in;

	/* OUT */
	uint64_t sec_out;
	uint64_t nsec_out;
	int ret;
};

/* UKVM_PORT_CLKSPEED */
struct ukvm_clkspeed {
	/* OUT */
	uint64_t clkspeed;
};

/* UKVM_PORT_BLKINFO */
struct ukvm_blkinfo {
	/* OUT */
	int sector_size;
	uint64_t num_sectors;
	int rw;
};

/* UKVM_PORT_BLKWRITE */
struct ukvm_blkwrite {
	/* IN */
	uint64_t sector;
	void *data;
	int len;
	
	/* OUT */
	int ret;
};

/* UKVM_PORT_BLKREAD */
struct ukvm_blkread {
	/* IN */
	uint64_t sector;
	void *data;

	/* IN/OUT */
	int len;
	
	/* OUT */
	int ret;
};

/* UKVM_PORT_NETINFO */
struct ukvm_netinfo {
	/* OUT */
	char mac_str[18];
};

/* UKVM_PORT_NETWRITE */
struct ukvm_netwrite {
	/* IN */
	void *data;
	int len;
	
	/* OUT */
	int ret;
};

/* UKVM_PORT_NETREAD */
struct ukvm_netread {
	/* IN */
	void *data;

	/* IN/OUT */
	int len;
	
	/* OUT */
	int ret;
};


#endif
