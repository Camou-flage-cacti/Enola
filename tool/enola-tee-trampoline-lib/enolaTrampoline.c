#include "enolaTrampoline.h"
void init_trampoline()
{
    To.arbitrary_cf = false;
    for(int i = 0; i <basicBlock_max; i++)
    {
        To.basicBlockStart[i] = -1;
        To.occurrence_count[i] = -1;
    }

    for(int i = 0; i <arbitrary_max; i++)
    {
        To.arbitrary_cf_addresses[i] = -1;
    }
}
/*TODO: implement secure trace storage for TA*/
void secure_trace_storage()
{
    printf("\r\n Debugging info: in the secure trace storage function =\r\n");
}
/*TODO Implement indirect branch analysis from the binary offline analysis data*/
void indirect_secure_trace_storage()
{
     printf("\r\n Debugging info: in the insecure trace storage function =\r\n");
}