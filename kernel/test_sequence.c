#include "solo5.h"
#include "ukvm/ukvm.h"
#include "ioport.h"

#define UNUSED(x) (void)(x)

int start_kernel(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);

    struct ukvm_getval gv;
    struct ukvm_putval pv;
    
    outl(UKVM_PORT_GETVAL, ukvm_ptr(&gv));
    cc_barrier();
    
    pv.value = gv.value + 1;
    outl(UKVM_PORT_PUTVAL, ukvm_ptr(&pv));
    cc_barrier();

    return 0;
}

