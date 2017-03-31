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

void rr_ukvm_puts(struct ukvm_puts *p, uint8_t *mem, int loc);
void rr_ukvm_boot_info(struct ukvm_boot_info *p, uint8_t *mem, int loc);
void rr_ukvm_blkinfo(struct ukvm_blkinfo *p, uint8_t *mem, int loc);
void rr_ukvm_blkwrite(struct ukvm_blkwrite *p, uint8_t *mem, int loc);
void rr_ukvm_blkread(struct ukvm_blkread *p, uint8_t *mem, int loc);
void rr_ukvm_netinfo(struct ukvm_netinfo *p, uint8_t *mem, int loc);
void rr_ukvm_netwrite(struct ukvm_netwrite *p, uint8_t *mem, int loc);
void rr_ukvm_netread(struct ukvm_netread *p, uint8_t *mem, int loc);
void rr_ukvm_poll(struct ukvm_poll *p, uint8_t *mem, int loc);
void rr_ukvm_time_init(struct ukvm_time_init *p, uint8_t *mem, int loc);

int rr_init(int m, char *rr_file, char *check_file);
#endif
