#ifndef __UKVM_RR_H__
#define __UKVM_RR_H__

enum {
    RR_LOC_IN = 1,
    RR_LOC_OUT,
};
enum {
    RR_MODE_RECORD = 1,
    RR_MODE_REPLAY,
};

extern int rr_mode;

void rr_ukvm_puts(struct platform *p, struct ukvm_puts *o, int loc);
void rr_ukvm_boot_info(struct platform *p, struct ukvm_boot_info *o, int loc);
void rr_ukvm_blkinfo(struct platform *p, struct ukvm_blkinfo *o, int loc);
void rr_ukvm_blkwrite(struct platform *p, struct ukvm_blkwrite *o, int loc);
void rr_ukvm_blkread(struct platform *p, struct ukvm_blkread *o, int loc);
void rr_ukvm_netinfo(struct platform *p, struct ukvm_netinfo *o, int loc);
void rr_ukvm_netwrite(struct platform *p, struct ukvm_netwrite *o, int loc);
void rr_ukvm_netread(struct platform *p, struct ukvm_netread *o, int loc);
void rr_ukvm_poll(struct platform *p, struct ukvm_poll *o, int loc);
void rr_ukvm_time_init(struct platform *p, struct ukvm_time_init *o, int loc);
void rr_ukvm_rdtsc(struct platform *p, uint64_t *new_tsc, int loc);
void rr_ukvm_rdrand(struct platform *p, uint64_t *r, int loc);

int rr_init(int m, char *rr_file, char *check_file);
#endif
