#include "pin_types.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#ifndef SYSCALL_MODEL_LOG
#define SYSCALL_MODEL_LOG 1
#endif

#if SYSCALL_MODEL_LOG == 1
#include "output.h"
#endif

typedef void (*MEMREADFUNCPTR)(ADDRINT syscall_pc, ADDRINT syscall_num,
                                ADDRINT addr, ADDRINT bytes_read);

typedef void (*MEMWRITEFUNCPTR)(ADDRINT syscall_pc, ADDRINT syscall_num, 
                  ADDRINT addr, ADDRINT bytes_written);

static inline void
Model_SysCall_Memops(ADDRINT syscall_pc, ADDRINT num, ADDRINT arg0, ADDRINT arg1,
                     ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5,
                     MEMREADFUNCPTR MemoryRead, MEMWRITEFUNCPTR MemoryWritten)
{
#define MEM_READ(addr, size) MemoryRead(syscall_pc, num, (addr), (size))
#define MEM_WRITE(addr, size) MemoryWritten(syscall_pc, num, (addr), (size))
  switch(num)
  {
    case SYS_write:
    case SYS_pwrite64:
      {
        MEM_READ(arg1, arg2);
      }
      break;
    case SYS_read:
    case SYS_pread64:
      {
        MEM_WRITE(arg1, arg2);
      }
      break;
    default:
      {
#if SYSCALL_MODEL_LOG == 1
        LOG(" WARNING: System Call Memory Operations Not Modeled!\n");
#endif
      }
  }
#undef MEM_READ
#undef MEM_WRITE
}

