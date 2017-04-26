#ifndef PIN_FORENSIX_SLICING_H
#define PIN_FORENSIX_SLICING_H

#include "readwrite.h" // DO NOT REMOVE!!!
#include "pin_inst_descriptor.h"
#include "pin_slice.h"

#define AGGRESSIVE_DEBUG 0

extern INSDESC* INS_model;  // "outside" model instruction
extern INSDESC* INS_entry;  // func entry model instruction
extern INSDESC* INS_exit;   // func exit model instruction


extern PIN_Slice SLICE;

extern INT* Monitored_Pid;
extern OS_THREAD_ID* Monitored_Thread;
extern PIN_MUTEX Monitored_Info_Mutex;

extern bool Models_On;

static inline BOOL Is_Monitored_Thread(INT pid, OS_THREAD_ID tid)
{
  PIN_MutexLock(&Monitored_Info_Mutex);
  register BOOL ret = (tid == *Monitored_Thread || tid == INVALID_OS_THREAD_ID) &&
                      (pid == *Monitored_Pid);
  PIN_MutexUnlock(&Monitored_Info_Mutex);
  return ret;
}
#define IsMainThread() Is_Monitored_Thread(PIN_GetPid(), PIN_GetTid())

/** Called by models **/
VOID __RegisterRead(INSDESC* ins, ADDRINT reg, ADDRINT value);
VOID __RegisterWritten(INSDESC* ins, ADDRINT reg, ADDRINT value);

#endif // PIN_FORENSIX_SLICING_H
