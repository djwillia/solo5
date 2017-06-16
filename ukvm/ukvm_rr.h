#ifndef __UKVM_RR_H__
#define __UKVM_RR_H__

enum {
    RR_LOC_IN = 1,
    RR_LOC_OUT,
};
enum {
    RR_MODE_NONE = 0,
    RR_MODE_RECORD = 1,
    RR_MODE_REPLAY,
};

extern int rr_mode;

void rr_ukvm_puts(struct ukvm_hv *hv, struct ukvm_puts *o, int loc);
void rr_ukvm_boot_info(struct ukvm_hv *hv, struct ukvm_boot_info *o, int loc);
void rr_ukvm_blkinfo(struct ukvm_hv *hv, struct ukvm_blkinfo *o, int loc);
void rr_ukvm_blkwrite(struct ukvm_hv *hv, struct ukvm_blkwrite *o, int loc);
void rr_ukvm_blkread(struct ukvm_hv *hv, struct ukvm_blkread *o, int loc);
void rr_ukvm_netinfo(struct ukvm_hv *hv, struct ukvm_netinfo *o, int loc);
void rr_ukvm_netwrite(struct ukvm_hv *hv, struct ukvm_netwrite *o, int loc);
void rr_ukvm_netread(struct ukvm_hv *hv, struct ukvm_netread *o, int loc);
void rr_ukvm_poll(struct ukvm_hv *hv, struct ukvm_poll *o, int loc);
void rr_ukvm_walltime(struct ukvm_hv *hv, struct ukvm_walltime *o, int loc);
void rr_ukvm_rdtsc(struct ukvm_hv *hv, uint64_t *new_tsc, int loc);
void rr_ukvm_rdrand(struct ukvm_hv *hv, uint64_t *r, int loc);

/* RR_INPUT or RR_INPUT_REDO
 *    (struct name, pointer to struct, offset for any data ptrs) 
 *    Redo re-performs the function (e.g., for console out) 
 */
#define _RR_INPUT(p,s,o,r) do {                             \
        if (rr_mode != RR_MODE_NONE) {                      \
            rr_ukvm_##s(p, o, RR_LOC_IN);                   \
            if (rr_mode == RR_MODE_REPLAY)                  \
                if(r) goto rr_output_##s;                   \
        }                                                   \
    } while (0)

#define RR_INPUT_REDO(p,s,o) _RR_INPUT(p,s,o,0)
#define RR_INPUT(p,s,o) _RR_INPUT(p,s,o,1)
          
#define RR_OUTPUT(p,s,o) do {                               \
        if (rr_mode != RR_MODE_NONE) {                      \
        rr_output_##s:                                      \
            rr_ukvm_##s(p, o, RR_LOC_OUT);                  \
        }                                                   \
    } while (0)

#endif
