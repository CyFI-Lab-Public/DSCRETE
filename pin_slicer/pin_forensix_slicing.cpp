#include "readwrite.h"
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <stack>
#include <vector>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "pin.H"

#include "pin_forensix_slicing.h"

#include "forensix_slicing_constants.h"
#include "pin_inst_descriptor.h"
#include "pin_rtn_descriptor.h"
#include "pin_slice.h"
#include "pin_debug_info.h"
#include "pin_slicing_model.h"

#if AGGRESSIVE_DEBUG == 0
#define SYSCALL_MODEL_LOG 0
#endif
#include "syscall_models.h"
#include "analysis_datatypes.h"
#undef NDEBUG
#include <cassert>

/** Two "maps" to record inst and rtn info **/
static Instructions INSTRUCTIONS;
static Routines     ROUTINES;

/** The Slice object traces and outputs the slicing info **/
PIN_Slice SLICE;

/** Debug object records human readable program info **/
static PIN_DebugInfoProducer DEBUG_INFO;

/** Important Instructions **/
static INSDESC* current_INS = NULL;
static INSDESC* prev_INS = NULL;

INSDESC* INS_model;  // "outside" model instruction
INSDESC* INS_entry;  // func entry model instruction
INSDESC* INS_exit;   // func exit model instruction

INT  Original_Pid; // the main executables pid
OS_THREAD_ID Original_Tid; // and thread id

INT* Monitored_Pid; // currently monitored stuff
OS_THREAD_ID* Monitored_Thread;
PIN_MUTEX Monitored_Info_Mutex;

static inline VOID
Set_Monitored_Thread(INT pid, OS_THREAD_ID tid)
{
  PIN_MutexLock(&Monitored_Info_Mutex);
  *Monitored_Pid = pid;
  *Monitored_Thread = tid;
  PIN_MutexUnlock(&Monitored_Info_Mutex);
#if AGGRESSIVE_DEBUG > 0
  LOG("Following it ... " + decstr(pid) + "(" + decstr(tid) + ")\n");
#endif
}

volatile bool* Follow_Forks_Vals;
volatile INT* Follow_Forks_Index;
volatile INT* Follow_Forks_Size;
PIN_MUTEX Follow_Forks_Mutex;

bool Models_On = false;

// Wait to turn on models until we have finished the loader's initialization.
bool _HoldingForFirstInst = true;
#define HoldingForFirstInst() (_HoldingForFirstInst)
#define OnFirstInst() \
  do { \
    _HoldingForFirstInst = false; \
    Models_On = true; \
  } while(0)


/** Wait until Instrumentation is turned on **/
volatile BOOL* INST_ON;
PIN_MUTEX INST_ON_Mutex;

static inline BOOL is_inst_on() {
  BOOL ret;
  PIN_MutexLock(&INST_ON_Mutex);
  ret = *INST_ON;
  PIN_MutexUnlock(&INST_ON_Mutex);
  return ret;
}

static inline VOID set_inst_on(BOOL b) {
  PIN_MutexLock(&INST_ON_Mutex);
  *INST_ON = b;
  PIN_MutexUnlock(&INST_ON_Mutex);
}


/** "Originial" instrumentation calls (Called for instructions in Main Executable) **/
#define FILTER_ANALYSIS_ROUTINE() \
  do { \
    if (!is_inst_on()) return; \
    if (!IsMainThread()) return; \
  } while(0)
/* LOG(format("%s IMP %d %d %d\n") % __func__ % IsMainThread() % PIN_GetPid() % PIN_GetTid()); */

/** Data Deps **/
VOID __RegisterRead(INSDESC* ins, ADDRINT reg, ADDRINT value)
{ /* Not static because it is called by models! */
#if AGGRESSIVE_DEBUG > 1
# if AGGRESSIVE_DEBUG < 3
  if(ins == INS_model)
# endif
    LOG(format("   Reg Read %s\n") % REG_StringShort((REG)reg));
#endif

  SLICE.RegisterRead(reg, value);
}
static VOID A_RegisterRead(INSDESC* ins, ADDRINT reg, const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE(); 
  assert (ins); 
  assert (ins == current_INS);
  PIN_REGISTER value;
  PIN_GetContextRegval(ctxt, (REG)reg, (UINT8*)&value);
  __RegisterRead(ins, reg, value.qword[0]); // the reg may be bigger than qword! Oh well... 
}

VOID __RegisterWritten(INSDESC* ins, ADDRINT reg, ADDRINT value)
{ /* Not static because it is called by models! */
#if AGGRESSIVE_DEBUG > 1
# if AGGRESSIVE_DEBUG < 3
  if(ins == INS_model)
# endif
    LOG(format("   Reg Written %s\n") % REG_StringShort((REG)reg));
#endif
  SLICE.RegisterWritten(reg);
}
static VOID A_RegisterWritten(INSDESC* ins, ADDRINT reg, const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE();
  assert (ins);
  assert (ins == current_INS);
  PIN_REGISTER value;
  PIN_GetContextRegval(ctxt, (REG)reg, (UINT8*)&value);
  __RegisterWritten(ins, reg, value.qword[0]);
}

static inline VOID __MemoryRead(INSDESC* ins, ADDRINT addr, ADDRINT size)
{
  while (size > 0)  {
    int read_size = (size > sizeof(ADDRINT) ? sizeof(ADDRINT) : size);

#if AGGRESSIVE_DEBUG > 1
# if AGGRESSIVE_DEBUG < 3
    if(ins == INS_model)
# endif
    LOG(format("  Mem Read %s - %s\n") % hexstr(addr) % hexstr(addr+read_size-1));
#endif

    ADDRINT value = PIN_ReadValue(addr, read_size);
    SLICE.MemoryRead(addr, read_size, value);

    size -= read_size;
    addr += read_size;
  }
}
static VOID A_MemoryRead(INSDESC* ins, ADDRINT addr, ADDRINT size)
{
  FILTER_ANALYSIS_ROUTINE();
  assert (ins);
  assert (ins == current_INS);
  __MemoryRead(ins, addr, size);
}

static inline VOID __MemoryWritten(INSDESC* ins, ADDRINT addr, ADDRINT size)
{
  while (size > 0)  {
      int write_size = (size > sizeof(ADDRINT) ? sizeof(ADDRINT) : size);

#if AGGRESSIVE_DEBUG > 1
# if AGGRESSIVE_DEBUG < 3
      if(ins == INS_model)
# endif
      LOG(format("  Mem Written %s - %s\n") % hexstr(addr) % hexstr(addr+write_size-1));
#endif

      SLICE.MemoryWritten(addr, write_size);

      size -= write_size;
      addr += write_size;
  }
}
static VOID A_MemoryWritten(INSDESC* ins, ADDRINT addr, ADDRINT size)
{
  FILTER_ANALYSIS_ROUTINE();
  assert (ins);
  assert (ins == current_INS);
  __MemoryWritten(ins, addr, size);
}

/** Instruction Ordering **/
static inline VOID __EnterInstruction(INSDESC* ins)
{
  current_INS = ins;
#if AGGRESSIVE_DEBUG > 2
  if (current_INS != INS_model) {
    LOG(format("P%d(T%d):") % PIN_GetPid() % PIN_GetTid());
    LOG(format("INST 0x%09x %ld <%lx>\n") % current_INS->addr % (current_INS->instance + 1) % (ADDRINT)current_INS);
  }
#endif

  if (HoldingForFirstInst() && current_INS != INS_model)
  {
    OnFirstInst();
  }    

  current_INS->instance = current_INS->instance + 1;
  assert(current_INS->instance < 0xfffffff0);
  
  SLICE.EnterInstruction(current_INS);
}
// Forward Decl.
static inline VOID __LeaveInstruction2(ADDRINT, const CONTEXT*);
static VOID A_EnterInstruction(INSDESC* ins, ADDRINT pc, const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE();
  if (current_INS == INS_model)
  { /* We must have missed the exit... like a plt JMP or something */
     __LeaveInstruction2(pc, ctxt);
  }

  assert (current_INS == NULL);
  assert (ins);
  
  ADDRINT a = ins->addr; // ensure assert works
  if (!a)
  {
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(pc);
#if AGGRESSIVE_DEBUG > 0
    IMG img = IMG_FindByAddress(pc);
    LOG(format("ins:0x%lx (%s:%s)\n") % pc 
          % (RTN_Valid(rtn) ? RTN_Name(rtn) : "")
          % (IMG_Valid(img) ? IMG_Name(img) : ""));
#endif
    ins = INSTRUCTIONS.find(pc);
    if(ins == NULL || !ins->addr) {
      ins = INSTRUCTIONS.NewINS(pc);
      DEBUG_INFO.Add(pc, rtn);
    }
    PIN_UnlockClient();
    a = ins->addr;    
    assert(a && "This instruction not in INSTRUCTIONS table!");
  }  
  __EnterInstruction(ins);
}

static inline VOID __LeaveInstruction (INSDESC* ins)
{
  prev_INS = current_INS;
  current_INS = NULL;
  
  SLICE.LeaveInstruction(prev_INS);
}
static VOID A_LeaveInstruction (INSDESC* ins)
{
  FILTER_ANALYSIS_ROUTINE();

  assert (ins == current_INS);
  __LeaveInstruction (ins);
}

/** Control Flow **/
/** Helpers **/
static inline VOID __EnterFunction()
{
  //LOG("EnterFunction\n");

  __EnterInstruction(INS_entry);
  __LeaveInstruction(INS_entry);
}

static inline VOID __LeaveFunction()
{
  //LOG("LeaveFunction\n");

  __EnterInstruction(INS_exit);
  __LeaveInstruction(INS_exit);
}

/** Control Flow CallBacks */
static VOID A_Call(INSDESC* insdesc, ADDRINT target)
{
  FILTER_ANALYSIS_ROUTINE();

  assert (current_INS == NULL);
  assert (insdesc);

#if AGGRESSIVE_DEBUG > 0
  LOG(format("CALL1 0x%09x -> 0x%09x(%s)\n")
        % insdesc->addr % target % RTN_FindNameByAddress(target));
#endif

  if (ADDR_IsMainExecutable(target)) {
    __EnterFunction();
  }
#if AGGRESSIVE_DEBUG > 0
  else
  {
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(target);
    IMG img = IMG_FindByAddress(target);
    PIN_UnlockClient();
    if (RTN_IsBlacklisted(rtn))
    {
      LOG(format("(blacklist) CALL %s<%s> from %s\n")
            % hexstr(target) % RTN_Name(rtn) % hexstr(insdesc->addr));
    }
    else
    {
      LOG(format("CALL1 %s<%s:%s> (outside?) from %s\n")
            % hexstr(target) % RTN_Name(rtn) % IMG_Name(img) % hexstr(insdesc->addr));
    }
  }
#endif
}

#if AGGRESSIVE_DEBUG > 0
/* This function is ONLY enabled during debugging because I don't
 * think we need it for anything... */
static VOID A_Jmp(INSDESC* insdesc, ADDRINT target)
{
  FILTER_ANALYSIS_ROUTINE();

  assert (current_INS == NULL);
  assert (insdesc);

  if (ADDR_IsMainExecutable(target))
  {
    /* Do we need to do anything here? If the jmp is local
       or if the jump is to another function, the CFG will 
       still think that it is all one function... thus the
       control dep will be computed as such. Is this ok? */
  }
#if AGGRESSIVE_DEBUG > 0
  else
  {
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(target);
    IMG img = IMG_FindByAddress(target);
    PIN_UnlockClient();
    if (RTN_IsBlacklisted(rtn))
    {
      LOG(format("(blacklist) JMP %s<%s> from %s\n")
            % hexstr(target) % RTN_Name(rtn) % hexstr(insdesc->addr));
    }
    else {
      LOG(format("JMP %s<%s:%s> (outside?) from %s\n")
            % hexstr(target) % RTN_Name(rtn) % IMG_Name(img) % hexstr(insdesc->addr));
    }
  }
#endif
}
#endif

static VOID A_Ret (INSDESC* insdesc, ADDRINT target)
{
  FILTER_ANALYSIS_ROUTINE();
  
  assert (current_INS == NULL);
  assert (insdesc);

#if AGGRESSIVE_DEBUG > 0
  LOG(format("RET1 0x%09x -> 0x%09x(%s)\n")
        % insdesc->addr % target % RTN_FindNameByAddress(target));
#endif

  __LeaveFunction();
}


/** "2" instrumentation calls (Called for instructions not in Main Executable) **/
#define FILTER_ANALYSIS_ROUTINE2() \
  do { \
    FILTER_ANALYSIS_ROUTINE(); \
    if (!Models_On) return; \
  } while(0)

/** Data Dep **/
static VOID A_MemoryRead2(ADDRINT pc, ADDRINT addr, ADDRINT size)
{
  FILTER_ANALYSIS_ROUTINE2();
  assert(current_INS == INS_model);
  __MemoryRead(current_INS, addr, size);
}

static VOID A_MemoryWritten2(ADDRINT pc, ADDRINT addr, ADDRINT size)
{
  FILTER_ANALYSIS_ROUTINE2();
  assert(current_INS == INS_model);
  __MemoryWritten(current_INS, addr, size);
}

/** Instruction Ordering **/
static VOID A_EnterInstruction2(ADDRINT pc, const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE2();

  /* Ensure that we are either: Entering a new model from the main exec OR Already in one */
#define ASSERTION (current_INS == INS_model || (prev_INS != INS_model && current_INS == NULL))
  if(!ASSERTION)
  {
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(pc);
    IMG img = IMG_FindByAddress(pc);
    PIN_UnlockClient();
    string rtnname = (RTN_Valid(rtn) ? RTN_Name(rtn) : "");
    string imgname = (IMG_Valid(img) ? IMG_Name(img) : "");

    LOG("\n***********\nFailed EnterInstruction2 Assertion\n");
    LOG("Possibly a non-modeled function called a modeled function!\n"
        "Need to add model for outer-most function!\n");
    LOG(format("pc: 0x%09x (%s:%s)\n") % pc % (rtnname) % (imgname));
    PIN_LockClient();
    IMG img2;
    if(current_INS == NULL)
      LOG("current_INS: NULL\n");
    else {
      img2 = IMG_FindByAddress(current_INS->addr);
      LOG(format("current_INS:instance: %d addr: 0x%09x (%s:%s)\n")
           % current_INS->instance % current_INS->addr
           % RTN_FindNameByAddress(current_INS->addr)
           % (IMG_Valid(img2) ? IMG_Name(img2) : ""));
    }
    img2 = IMG_FindByAddress(prev_INS->addr);
    LOG(format("prev_INS:instance: %d addr: 0x%09x (%s:%s)\n")
         % prev_INS->instance % prev_INS->addr
         % RTN_FindNameByAddress(prev_INS->addr)
         % (IMG_Valid(img2) ? IMG_Name(img2) : ""));
    
    PIN_UnlockClient();
    assert(ASSERTION);
  }
#undef ASSERTION

  /* If we got here we are either: Entering a new model from the main exec OR Already in one */

#if AGGRESSIVE_DEBUG > 1 // this controls stuff below!
  PIN_LockClient();
  RTN rtn = RTN_FindByAddress(pc);
  IMG img = IMG_FindByAddress(pc);
  PIN_UnlockClient();
  string rtnname = (RTN_Valid(rtn) ? RTN_Name(rtn) : ("rtn_0x" + hexstr(pc)));
  string imgname = (IMG_Valid(img) ? IMG_Name(img) : "");
  LOG(format("P%d(T%d):INST2 pc:0x%09x (%s:%s)\n") 
       % PIN_GetPid() % PIN_GetTid()
       % pc 
       % rtnname
       % imgname);
#endif

  if (current_INS == NULL)
  {
#if !(AGGRESSIVE_DEBUG > 1) // If > 1 then we already looked this stuff up!
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(pc);
    IMG img = IMG_FindByAddress(pc);
    PIN_UnlockClient();
    string rtnname = (RTN_Valid(rtn) ? RTN_Name(rtn) : ("rtn_0x" + hexstr(pc)));
    string imgname = (IMG_Valid(img) ? IMG_Name(img) : "");
#endif
#if AGGRESSIVE_DEBUG > 0
    LOG(format("Entering Model Instruction:\ninstance: %d pc: 0x%09x (%s:%s)\n") 
         % (INS_model->instance + 1) % pc % rtnname % imgname);
#endif 
    __EnterInstruction(INS_model);
    DEBUG_INFO.AddModel(INS_model->instance, *prev_INS, rtnname+"@"+imgname);
    Enter_Model(rtn, rtnname, img, imgname, ctxt, prev_INS);
  }
}

/**
 * Leave the model instruction.
 *
 * Please note: This function is NOT called by PIN, but rather by any place where we are
 * leaving an "outside" instruction and entering a "local" instruction.
 * Right now these places are: A_Call2 (for callbacks), A_Jmp2 (for jmp-callbacks),
 *   A_Ret2 (for model returns), ThreadFini (when the prog. ends), A_Exit (same as ThreadFini), A_EnterInstruction (for anything else).
 */
static inline VOID __LeaveInstruction2(ADDRINT pc, const CONTEXT* ctxt)
{
  Leave_Model(ctxt);
  __LeaveInstruction(INS_model);
}

/** Control Flow **/
#define LOG_SPECIAL(p, t) \
  LOG(format("%s 0x%09x(%s:%s) -> 0x%09x(%s:%s)\n") \
        % __func__ \
        % p % RTN_FindNameByAddress(p) % IMG_FindNameByAddress(p) \
        % t % RTN_FindNameByAddress(t) % IMG_FindNameByAddress(t))
  
static VOID A_Call2(ADDRINT pc, ADDRINT target, const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE2();
  assert(current_INS == INS_model);

  /* LOG  */
#if AGGRESSIVE_DEBUG > 0
  LOG_SPECIAL(pc, target);
#endif 

  if (ADDR_IsMainExecutable(target)) {
    /* Callback? */
    __LeaveInstruction2(pc, ctxt);
    // __EnterFunction();
  }
}

static VOID A_Jmp2(ADDRINT pc, ADDRINT target, const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE2();
  assert (current_INS == INS_model);

  /* LOG */
#if AGGRESSIVE_DEBUG > 0
  LOG_SPECIAL(pc, target);
#endif 
  
  if (ADDR_IsMainExecutable(target)) {
    __LeaveInstruction2(pc, ctxt);
    // __EnterFunction();
  }
}

static VOID A_Ret2 (ADDRINT pc, ADDRINT target, const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE2();
  assert (current_INS == INS_model);

  /* LOG */
#if AGGRESSIVE_DEBUG > 0
  LOG_SPECIAL(pc, target);
#endif 
  
  if (ADDR_IsMainExecutable(target)) {
    __LeaveInstruction2(pc, ctxt);
  }
}
#undef LOG_SPECIAL

static VOID SysMemRead(ADDRINT syscall_pc, ADDRINT syscall_num, 
                       ADDRINT addr, ADDRINT bytes_read)
{
    __MemoryRead(current_INS, addr, bytes_read);
}

static VOID SysMemWritten(ADDRINT syscall_pc, ADDRINT syscall_num, 
                       ADDRINT addr, ADDRINT bytes_written)
{
    __MemoryWritten(current_INS, addr, bytes_written);
}

static VOID A_SysBefore2(ADDRINT pc, ADDRINT num, ADDRINT arg0, ADDRINT arg1,
                         ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
  FILTER_ANALYSIS_ROUTINE2();

#if AGGRESSIVE_DEBUG > 0
  static struct {
    ADDRINT num_args;
    string  name;
  } syscalls[] = {
    #include "../include/syscallent.h"
    };
  LOG(format("SYSCALL @ 0x%lx: %s(") % pc % syscalls[num].name.c_str());
# define SHOW_ARG(n) \
   do { \
     if (n < syscalls[num].num_args) { \
       LOG(format(" %lx") % arg##n ); \
       if (n+1 != syscalls[num].num_args) \
         LOG(","); \
     } \
   } while (0)
  SHOW_ARG(0);
  SHOW_ARG(1);
  SHOW_ARG(2);
  SHOW_ARG(3);
  SHOW_ARG(4);
  SHOW_ARG(5);
# undef SHOW_ARG
  LOG(")\n");
#endif
  
  Model_SysCall_Memops(pc, num, arg0, arg1, arg2, arg3, arg4, arg5,
                        SysMemRead, SysMemWritten);
}

/** Other Functions ;) **/
#define alloc_multiproc_shared_mem(size) \
    mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)

static VOID Init()
{
  Original_Pid = PIN_GetPid();
  Original_Tid = PIN_GetTid();

  Monitored_Pid = (INT*)alloc_multiproc_shared_mem(sizeof(INT));
  assert(Monitored_Pid);
  Monitored_Thread = (OS_THREAD_ID*)alloc_multiproc_shared_mem(sizeof(OS_THREAD_ID));
  assert(Monitored_Thread);
  PIN_MutexInit(&Monitored_Info_Mutex);

  /* Always start monitoring the main thread! */
  *Monitored_Pid = Original_Pid;
  *Monitored_Thread = Original_Tid;
  LOG("PID: "+decstr(*Monitored_Pid)+" TID: "+decstr(*Monitored_Thread)+"\n");
  
  INS_model = INSTRUCTIONS.NewINS(MODEL_INST_ADDR);
  INS_entry = INSTRUCTIONS.NewINS(ENTRY_INST_ADDR);
  INS_exit  = INSTRUCTIONS.NewINS(EXIT_INST_ADDR);
  assert(INS_exit->addr == EXIT_INST_ADDR);
  LOG(format("INS_model 0x%lx, INS_entry 0x%lx INS_exit 0x%lx\n")
        % INS_model->addr % INS_entry->addr % INS_exit->addr);
 
  DEBUG_INFO.AddFake(INS_entry->addr, ENTRY_INST_NAME);
  DEBUG_INFO.AddFake(INS_exit->addr, EXIT_INST_NAME);

  DEBUG_INFO.Import(DEBUG_FILE_NAME);
  SLICE.Init();

  INST_ON = (BOOL*)alloc_multiproc_shared_mem(sizeof(BOOL));
  assert(INST_ON);
  PIN_MutexInit(&INST_ON_Mutex);
  *INST_ON = true;
}

static VOID Fini(INT32 code, VOID* v)
{
  FILTER_ANALYSIS_ROUTINE();
  LOG(format("P%d(T%d) ********** Fini ****************\n")
        % PIN_GetPid() % PIN_GetTid());
  SLICE.Fini();
  DEBUG_INFO.Export(DEBUG_FILE_NAME);
  ShutdownModels();
  Set_Monitored_Thread(-1, -1);
  set_inst_on(false);
}

static inline bool FollowThreadPrompt()
{
  register bool ret;
  PIN_MutexLock(&Follow_Forks_Mutex);
  register INT index = *Follow_Forks_Index;
  register INT size = *Follow_Forks_Size;

#if AGGRESSIVE_DEBUG > 0
  LOG(format("FF: index:%d size:%d val:%s\n")
    % index % size
    % ((index < size ? Follow_Forks_Vals[index] : true) ?
         "true" : "false"));
#endif

  if (size == 0)
    ret = true;
  else {
    ret = Follow_Forks_Vals[index];
    index++;
    if(index < size)
      (*Follow_Forks_Index) = index;
  }
  PIN_MutexUnlock(&Follow_Forks_Mutex);
  return ret;
}

static VOID ThreadStart(THREADID do_not_usetid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
  INT pid = PIN_GetPid();
#if AGGRESSIVE_DEBUG > 0
  PIN_MutexLock(&Monitored_Info_Mutex);
  LOG(format("FF: P: %d T: %d MP: %d MT: %d\n") 
       % pid % PIN_GetTid() % *Monitored_Pid % *Monitored_Thread);
  PIN_MutexUnlock(&Monitored_Info_Mutex);
#endif

  if(Is_Monitored_Thread(pid, PIN_GetParentTid()) && FollowThreadPrompt())
  {
    Set_Monitored_Thread(pid, PIN_GetTid());
  }
#if AGGRESSIVE_DEBUG > 0
  else
  {
    LOG(format("Not Following ... %d(%d) FORK\n") % PIN_GetPid() % PIN_GetTid());
  }
#endif
}

static VOID ThreadFini(THREADID do_not_usetid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
  FILTER_ANALYSIS_ROUTINE();
  INT pid = PIN_GetPid();
  OS_THREAD_ID tid = PIN_GetTid();
  LOG("-- THREAD " + decstr(pid) + "(" + decstr(tid) + ") FINISH\n");
  
  if(current_INS == INS_model)
    __LeaveInstruction2(current_INS->addr, ctxt);
  Models_On = false;

  Fini(0,NULL);
}

static VOID ForkBefore(THREADID do_not_usetid, const CONTEXT* ctxt, VOID*)
{
  LOG("FORK before - " + decstr(PIN_GetPid()) + "\n");
}

static VOID ForkChild(THREADID do_not_usetid, const CONTEXT* ctxt, VOID*)
{
#if AGGRESSIVE_DEBUG > 0
  PIN_MutexLock(&Monitored_Info_Mutex);
  LOG(format("FF: P: %d T: %d MP: %d MT: %d\n") 
       % PIN_GetPid() % PIN_GetTid() % *Monitored_Pid % *Monitored_Thread);
  PIN_MutexUnlock(&Monitored_Info_Mutex);
#endif

  if(Is_Monitored_Thread(getppid(), PIN_GetParentTid()) && FollowThreadPrompt())
  { 
    Set_Monitored_Thread(PIN_GetPid(), PIN_GetTid());
  } 
#if AGGRESSIVE_DEBUG > 0
  else
  {
    LOG(format("Not Following ... %d FORK\n") % PIN_GetPid());
  }
#endif
}

static VOID A_Exit(const CONTEXT* ctxt)
{
  FILTER_ANALYSIS_ROUTINE();
  LOG(format("P%d(T%d):") % PIN_GetPid() % PIN_GetTid());
  LOG("MADE CALL TO EXIT\n");
  if(current_INS == INS_model)
    __LeaveInstruction2(current_INS->addr, ctxt);
  Models_On = false;
  Fini(0,NULL);
}

/* ===================================================================== */
/* Instrument Functions                                                  */
/* ===================================================================== */

static inline VOID
Instrument_exit_func(IMG img)
{
  RTN rtn = RTN_FindByName(img, "exit");
  if (RTN_Valid(rtn)) {
    LOG(format("Instrument exit in %s\n") % IMG_Name(img));
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)(A_Exit),
                  IARG_CONST_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
    RTN_Close(rtn);
  }
}

static VOID InstrumentIMG(IMG img, VOID*)
{
  LOG(format("IMG 0x%09x - 0x%09x : %s\n")
          % IMG_LowAddress(img) % IMG_HighAddress(img) % IMG_Name(img));
  
  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) 
  {
    LOG(format(" SEC 0x%09x - 0x%09x : %s\n")
          % SEC_Address(sec) % (SEC_Address(sec)+SEC_Size(sec)) % SEC_Name(sec));

    for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) 
    {
      if(IsMainExecutable(img, rtn))
      {
        RTN_Open(rtn);
        for ( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) ) {
          INSTRUCTIONS.NewINS(ins);
          DEBUG_INFO.Add(ins);
        }
        DEBUG_INFO.Add(rtn);
        RTN_Close(rtn);
      }
    }
  }

  if(IMG_IsMainExecutable(img)) {
    LOG("  main executable : " + IMG_Name(img) + "\n");
  }

  Instrument_exit_func(img);
}


static VOID InstrumentINS(INS ins, VOID*)
{
#define INS_InsertCallBefore(funptr, ... ) \
  INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)(funptr), __VA_ARGS__)

#define INS_InsertCallAfter(funptr, ...) \
  do { \
    if (INS_HasFallThrough(ins)) \
      INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)(funptr), __VA_ARGS__); \
    if (INS_IsBranchOrCall(ins)) \
      INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)(funptr), __VA_ARGS__); \
  } while(0)


  if (ADDR_IsMainExecutable(INS_Address(ins))) 
  {
    assert(!INS_IsSyscall(ins));
    // I just haven't handled syscalls in the binary yet!

    INSDESC& insdesc = INSTRUCTIONS[ins];
    INS_InsertCallBefore(A_EnterInstruction,
                         IARG_PTR, &insdesc,
                         IARG_INST_PTR,
                         IARG_CONST_CONTEXT,
                         IARG_CALL_ORDER, CALL_ORDER_FIRST + 1, 
                         IARG_END);

#define HANDLE_REG_FUNC(funptr, r, order) \
  INS_InsertCallBefore (funptr, \
                        IARG_PTR, &insdesc, \
                        IARG_ADDRINT, (ADDRINT)r, \
                        IARG_CONST_CONTEXT, \
                        IARG_CALL_ORDER, CALL_ORDER_FIRST + (order), \
                        IARG_END)
#define HANDLE_REG_READ(r) HANDLE_REG_FUNC(A_RegisterRead, r, 5)
#define HANDLE_REG_WRITE(r) HANDLE_REG_FUNC(A_RegisterWritten, r, 20)

#define HANDLE_REG(func, r) \
  do { \
    if(!REG_is_x87_reg(r)) /* x87 flags reg cannot be read directly */  \
      HANDLE_REG_ ## func (r); \
  } while (0) 

    /* Reg reads */
    for (UINT32 i = 0, e = INS_MaxNumRRegs(ins); i < e; ++i) {
      REG reg = REG_FullRegName(INS_RegR(ins, i));
      HANDLE_REG(READ, reg);
    }

    /* Reg writes */
    for (UINT32 i = 0, e = INS_MaxNumWRegs(ins); i < e; ++i) {
      REG reg = REG_FullRegName(INS_RegW(ins, i));
      HANDLE_REG(WRITE, reg);
    }

#undef HANDLE_REG
#undef HANDLE_REG_READ
#undef HANDLE_REG_WRITE
#undef HANDLE_REG_FUNC

#define HANDLE_MEM(funptr, op, order) \
  INS_InsertCallBefore (funptr, \
                        IARG_PTR, &insdesc, IARG_MEMORYOP_EA, op, \
                        IARG_ADDRINT, (ADDRINT)INS_MemoryOperandSize(ins, op), \
                        IARG_CALL_ORDER, CALL_ORDER_FIRST + (order), IARG_END)
#define HANDLE_MEM_READ(funptr, op) HANDLE_MEM(funptr, op, 5)
#define HANDLE_MEM_WRITE(funptr, op) HANDLE_MEM(funptr, op, 20)
    for (UINT32 i = 0, e = INS_MemoryOperandCount(ins); i < e; ++i) {
      /* Mem reads */
      if (INS_MemoryOperandIsRead(ins, i)) {
        HANDLE_MEM_READ(A_MemoryRead, i);
      }

      /* Mem writes */
      if (INS_MemoryOperandIsWritten(ins, i)) {
        HANDLE_MEM_WRITE(A_MemoryWritten, i);
      }
    }
#undef HANDLE_MEM
#undef HANDLE_MEM_WRITE
#undef HANDLE_MEM_READ

    // INST IS EXECUTED HERE
    
    INS_InsertCallAfter (A_LeaveInstruction,
                         IARG_PTR, &insdesc,
                         IARG_CALL_ORDER, CALL_ORDER_FIRST + 30,
                         IARG_END);

#define HANDLE_SPECIAL(funptr) \
  INS_InsertCallAfter(funptr, IARG_PTR, &insdesc, IARG_BRANCH_TARGET_ADDR, \
                      IARG_CALL_ORDER, CALL_ORDER_FIRST + 35, IARG_END); \
    /* Special cases */
    if (INS_IsCall(ins))
      HANDLE_SPECIAL(A_Call);

    if (INS_IsRet(ins))
      HANDLE_SPECIAL(A_Ret);

#if AGGRESSIVE_DEBUG > 0
    if (INS_IsBranch(ins))
      HANDLE_SPECIAL(A_Jmp);
#endif
#undef HANDLE_SPECIAL

  }
  else if(!IMG_IsLibLinux(INS_Img(ins)) && !RTN_IsBlacklisted(INS_Rtn(ins)))
  { /* Not the main exec and not the loader and not a blacklisted function */
    if (INS_IsSyscall(ins))
    { // Arguments and syscall number is only available before
      INS_InsertCallBefore(A_SysBefore2,
                       IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                       IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                       IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                       IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                       IARG_END);
    }
    else
    {
      INS_InsertCallBefore(A_EnterInstruction2,
                           IARG_INST_PTR,
                           IARG_CONST_CONTEXT,
                           IARG_CALL_ORDER, CALL_ORDER_FIRST + 1, 
                           IARG_END);

#define HANDLE_MEM2(funptr, op, order) \
  INS_InsertCallBefore (funptr, IARG_INST_PTR, IARG_MEMORYOP_EA, op, \
                        IARG_ADDRINT, (ADDRINT)INS_MemoryOperandSize(ins, op), \
                        IARG_CALL_ORDER, CALL_ORDER_FIRST + (order), IARG_END)
#define HANDLE_MEM2_READ(funptr, op) HANDLE_MEM2(funptr, op, 5)
#define HANDLE_MEM2_WRITE(funptr, op) HANDLE_MEM2(funptr, op, 20)
      for (UINT32 i = 0, e = INS_MemoryOperandCount(ins); i < e; ++i) {
        /* Mem reads */
        if (INS_MemoryOperandIsRead(ins, i)) {
          HANDLE_MEM2_READ(A_MemoryRead2, i);
        }
       
        /* Mem writes */
        if (INS_MemoryOperandIsWritten(ins, i)) {
          HANDLE_MEM2_WRITE(A_MemoryWritten2, i);
        }
      }
#undef HANDLE_MEM2
#undef HANDLE_MEM2_WRITE
#undef HANDLE_MEM2_READ
 
    // INST IS EXECUTED HERE

#define HANDLE_SPECIAL2(funptr) \
  INS_InsertCallAfter(funptr, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, \
                     IARG_CONST_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_FIRST + 30, IARG_END);
      if (INS_IsRet(ins))
        HANDLE_SPECIAL2(A_Ret2);

      if (INS_IsCall(ins))
        HANDLE_SPECIAL2(A_Call2);
    
      if (INS_IsBranch(ins))
        HANDLE_SPECIAL2(A_Jmp2);
#undef HANDLE_SPECIAL2
    }
  }
#undef INS_InsertCallBefore
#undef INS_InsertCallAfter
}

static BOOL HandleSignal(THREADID do_not_usetid, INT32 sig, CONTEXT *from,
                         BOOL hasHandler, const EXCEPTION_INFO *except_info, VOID *v)
{
  LOG(format("(%d) SIGNAL (%d) %s\n") % PIN_GetPid() % sig
        % (except_info ? PIN_ExceptionToString(except_info) : ""));
  return true;
}

static BOOL DebugInterpreter(THREADID do_not_usetid, CONTEXT *ctxt, const string &cmd, string *result, VOID *)
{
  std::string line = cmd;
  if(line == "inst on") {
    set_inst_on(true);
    Set_Monitored_Thread(PIN_GetPid(), PIN_GetTid());
    *result = "Should be on...\n";
    return true;
  }
  else if (line == "inst off") {
    set_inst_on(false);
    *result = "Should be off...\n";
    return true;
  }
  return false;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

static INT32 Usage()
{
  cerr << "This tool counts the number of dynamic instructions executed" << endl;
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */
KNOB<string> KnobFollowForks(KNOB_MODE_WRITEONCE, "pintool",
    "ff", "", "Follow Forks File");
KNOB<INT> KnobInstOff(KNOB_MODE_WRITEONCE, "pintool",
    "inst_off", "0", "Instrumentation off by default (default 0)");

static VOID Import_Follow_Forks(string filename) {
  vector<INT> read;
  FILE *ff = fopen(filename.c_str(), "rt");
  if(ff != NULL)
  {
    INT d;
    while(fscanf(ff, "%d", &d) == 1) {
      assert(d == 0 || d == 1);
      read.push_back(d);
    }
    fclose(ff);
  }

  Follow_Forks_Vals = (bool*)alloc_multiproc_shared_mem(sizeof(bool) * read.size());
  assert(Follow_Forks_Vals);
  Follow_Forks_Index = (INT*)alloc_multiproc_shared_mem(sizeof(INT));
  assert(Follow_Forks_Index);
  *Follow_Forks_Index = 0;
  Follow_Forks_Size = (INT*)alloc_multiproc_shared_mem(sizeof(INT));
  assert(Follow_Forks_Size);
  *Follow_Forks_Size = read.size();
  PIN_MutexInit(&Follow_Forks_Mutex);

  LOG("Import Follow Forks:");
  for(UINT i = 0; i < read.size(); i++) {
    Follow_Forks_Vals[i] = read.at(i) != 0;
    LOG(format("%d(%s) ") % read.at(i) % (Follow_Forks_Vals[i] ? "true" : "false")); 
  }  
  LOG("\n");
}

int main(int argc, char* argv[])
{
  // Initialize pin
  if (PIN_Init(argc, argv)) { return Usage(); }
  PIN_InitSymbols();
  if(PIN_InitSymbolsAlt(IFUNC_SYMBOLS) != TRUE)
  { 
    LOG("Error Reading IFUNC Symbols?\n");
  }

  Import_Follow_Forks(KnobFollowForks.Value());

  Init();

  if(KnobInstOff.Value() == 1) {
    set_inst_on(false);
    LOG("Instrumentation off by command line!\n");
  }

  // Register InstrumentINS to be called to instrument instructions

  IMG_AddInstrumentFunction(InstrumentIMG, 0);
  INS_AddInstrumentFunction(InstrumentINS, 0);

  // Register Fini to be called when A TRACED PROCESS (hint: forking) exits
  PIN_AddFiniFunction(Fini, 0);

  PIN_AddThreadStartFunction(ThreadStart, 0);
  PIN_AddThreadFiniFunction(ThreadFini, 0);

  PIN_AddForkFunction(FPOINT_BEFORE, ForkBefore, 0);
  PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChild, 0);

  INT32 sigs[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                   13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                   23, 24, 25, 26, 27, 28, 29, 30, 31, 34,
                   35, 36, 37, 38, 39, 40,41,42,43,44,45,
                   46,47,48,49,50,51,52,53,54,55,56,57,58,
                   59,60,61,62,63,64};
  INT32 n_sigs = (sizeof(sigs) / sizeof(INT32));

  for(INT32 i = 0; i < n_sigs; i++)
    PIN_InterceptSignal(sigs[i], HandleSignal, 0);

  PIN_AddDebugInterpreter(DebugInterpreter, NULL);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
