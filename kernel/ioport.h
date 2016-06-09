#ifndef __IOPORT_H__
#define __IOPORT_H__

/* accessing devices via port space */

static inline void outb(uint16_t port, uint8_t v){
    __asm__ __volatile__("outb %0,%1" : : "a" (v), "dN" (port));
}
static inline void outw(uint16_t port, uint16_t v){
    __asm__ __volatile__("outw %0,%1" : : "a" (v), "dN" (port));
}
static inline void outl(uint16_t port, uint32_t v){
    __asm__ __volatile__("outl %0,%1" : : "a" (v), "dN" (port));
}
static inline uint8_t inb(uint16_t port){
    uint8_t v;
    __asm__ __volatile__("inb %1,%0" : "=a" (v) : "dN" (port));
    return v;
}
static inline uint16_t inw(uint16_t port){
    uint16_t v;
    __asm__ __volatile__("inw %1,%0" : "=a" (v) : "dN" (port));
    return v;
}
static inline uint32_t inl(uint16_t port){
    uint32_t v;
    __asm__ __volatile__("inl %1,%0" : "=a" (v) : "dN" (port));
    return v;
}

static inline uint64_t inq(uint16_t port_lo){
    uint16_t port_hi = port_lo + 4;
    uint32_t lo, hi;
    
    __asm__ __volatile__("inl %1,%0" : "=a" (lo) : "dN" (port_lo));
    __asm__ __volatile__("inl %1,%0" : "=a" (hi) : "dN" (port_hi));

    return ((uint64_t)lo) | ((uint64_t)hi << 32);
}

/* compiler-only memory "barrier" */
#define cc_barrier() __asm__ __volatile__("": : :"memory")

#endif
