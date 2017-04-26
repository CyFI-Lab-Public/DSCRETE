#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

//#define BUILD_SCANNER
#undef BUILD_SCANNER

#include "pin.H"

#include "pin_forensix_scanner.h"
#ifdef BUILD_SCANNER
#undef AGGRESSIVE_LOGGING
#define AGGRESSIVE_LOGGING 1
#endif

#define ONE_RESULT
//#undef ONE_RESULT

#include "pin_crit_funcs.h"

#include "pin_scan.h"

#include "pin_helper.h"
#include "pin_scan_slaves.h"
#include "analysis_datatypes.h"

#ifdef BUILD_SCANNER
# include "pin_dep_guesser.h"
#endif

//#define STATISTICS
#undef STATISTICS
#ifdef STATISTICS
//# define  HARD_DEBUG // requires STATISTICS
map <ADDRINT, INT> addr2size;
static inline VOID Call_On_Every_Instruction(ADDRINT insaddr, INT inssize)
{
  if(is_slave) {
#ifdef HARD_DEBUG
    INT my_pid = PIN_GetPid();
    PIN_LockClient();
    IMG img = IMG_FindByAddress(insaddr);
    if(IMG_Valid(img))
      LOG(format("INST(%d): %lx + %s <%s>\n") % my_pid % (insaddr  - IMG_LowAddress(img)) % IMG_Name(img) % RTN_FindNameByAddress(insaddr));
    PIN_UnlockClient();
#endif
    addr2size[insaddr] = inssize;  
  }
}
#endif

#ifdef GTK_OUTPUT_ON
static PIN_Scan_Graphical SCANNER;
#else
static PIN_Scan SCANNER;
#endif

static PIN_Critical_Funcs_Handler Crit_Funcs;
static PIN_Address_Translator trans;

#ifdef BUILD_SCANNER
static string AnalysisDir;
static vector<ClosurePoint> PossibleClosures;
volatile static ADDRINT *CurrentClosureIndex;
static PIN_MUTEX *Closure_Index_Mutex;
static inline VOID Try_Claim_New_DEP_Inst(ADDRINT test_index)
{
  PIN_MutexLock(Closure_Index_Mutex);
  if((*CurrentClosureIndex) == (ADDRINT)-1 && !(PossibleClosures[test_index].done))
    *CurrentClosureIndex = test_index;
  PIN_MutexUnlock(Closure_Index_Mutex);
}
static inline BOOL All_Closures_Done()
{
  register bool ret = true;
  PIN_MutexLock(Closure_Index_Mutex);
  for(ClosurePoint c : PossibleClosures)
  {
    if(!c.done)
    {
      ret = false;
      break;
    }
  }
  PIN_MutexUnlock(Closure_Index_Mutex);
  return ret;
}
static inline BOOL Is_Current_DEP_Instruction(ADDRINT test_index)
{
  register bool ret;
  PIN_MutexLock(Closure_Index_Mutex);
  ret = (*CurrentClosureIndex) == test_index;
  PIN_MutexUnlock(Closure_Index_Mutex);
  return ret;
}
# define NEW_SCANNER_INFO_DIR "./scanner_info"
static inline void
Output_Scanner_Info_File(UINT32 dep_index)
{
  string scanner_info_filename = (format(NEW_SCANNER_INFO_DIR"/scanner%d.info")
                                    % dep_index).str();
  FILE *sif = fopen(scanner_info_filename.c_str(), "wt");
  fputs(PossibleClosures[dep_index].ToString().c_str(), sif);
  fclose(sif);
}
#else
static ClosurePoint Closure;
#endif

static INT Scanner_Master_Pid;
Slave_Proc_Info *Slave_PIDs;
UINT32 Slave_PIDs_Count;
UINT32 max_threads_count;
UINT32 current_max_threads_count;

/* ALWAYS check is_slave instead of waisting CPU cycles to if your pid is in the list! */
bool is_slave = false; // am I a slave?
static bool __is_slave = false; // is_slave can be changed. This is ALWAYS true for slaves.

#ifndef ONE_RESULT
static ADDRINT Saved_SP;
#endif

static time_t save;
#define SAVE_TIME() save = time(0);
#define LOG_TIME() \
  do { \
    double diff_sec = difftime(time(0), save); \
    unsigned int minutes = 0, hours = 0; \
    while(diff_sec > 60.0) { \
      minutes++; \
      diff_sec-=60.0; \
    } \
    while(minutes > 60) { \
      hours++; \
      minutes-=60; \
    } \
    LOG(format("Time: Hours: %d Minutes: %d Seconds: %.f\n") \
          % hours % minutes % diff_sec); \
  } while (0)

/**
 * Force the guest to fork.
 *
 * Before this returns, the Fork callbacks (if any) will be called!
 */
static inline INT guest_fork(const CONTEXT *ctxt) {
  INT ret = 1;
  PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
                              CALLINGSTD_DEFAULT, (AFUNPTR)fork,
                              PIN_PARG(ADDRINT), &ret,
                              PIN_PARG_END());
  return ret;
}

#define I_Am_The_Scanner_Master() (Scanner_Master_Pid == PIN_GetPid())
#define Is_Scanning_Master_Alive() (Scanner_Master_Pid != -1) 
#define Claim_Scanner_Master() \
  do { \
    Scanner_Master_Pid = PIN_GetPid(); \
  } while(0)
#define Release_Scanner_Master() \
  do { \
    Scanner_Master_Pid = -1; \
  } while(0)


static inline VOID 
Setup_Scan (const CONTEXT* ctxt, ADDRINT pc, THREADID tid
#ifdef BUILD_SCANNER
            , ADDRINT dep_index
#endif
            )
{
#define PIN_HANDLE_STUFF_AND_LOOP_BACK_TO_TOP() PIN_ExecuteAt(ctxt)

#ifdef BUILD_SCANNER
  Try_Claim_New_DEP_Inst(dep_index);
  if(!Is_Current_DEP_Instruction(dep_index)) return;
  const DEP& dep = PossibleClosures[dep_index].d;
  PossibleClosures[dep_index].done = true;
  OutputGuessFile(AnalysisDir, PossibleClosures);
#else
  const DEP& dep = Closure.d;
#endif

  if(!Is_Scanning_Master_Alive())
  {
    Claim_Scanner_Master();

    /** Boom! We have hit the magic instruction! 
     *  The process/thread that reached this point will
     *  become the scanner "master" spawning all other
     *  scanner threads... */

    SCANNER.Prime_Tool();
 
#ifdef BUILD_SCANNER
    /* Start the scanner on the expected place in the memory image */
    if(!SCANNER.Set_Next_Address(dep.value))
    {
      LOG(format("FATAL ERROR: Cannot Set Next Address "
                 "To %lx\nCheck Memory Maps!") % dep.value);
    }
#endif

    LOG(format("Hit 0x%lx (%d)(%s:%lx)\n Scanner Tool Primed\n") 
         % dep.ii.addr 
#ifdef BUILD_SCANNER
         % dep_index 
         % PossibleClosures[dep_index].img_name 
         % PossibleClosures[dep_index].offset
#else
         % 0
         % Closure.img_name 
         % Closure.offset
#endif
       );

    SAVE_TIME();
  }

  /* Should skip to here on second, third, ... calls. */
  if(I_Am_The_Scanner_Master())
  {
make_slave:
#ifdef BUILD_SCANNER
    if(SCANNER.Get_Current_Address() == dep.value)
#else
    if(!SCANNER.Done() && can_add_slaves())
#endif
    {
      // Force the process to fork
      INT ret = guest_fork(ctxt);
      if (ret == 0)
      {
        // In child...
        is_slave = true;
        __is_slave = true;
        return;
        // The child now runs until Start_Scan is called
      }
    
      // Only the parent will get here    
      add_slave_pid(ret);
      SCANNER.Go_To_Next_Address();
    }
    else { // cannot add slaves
      PIN_Yield();
      try_reclaim_all_possible_children();
    }

    if(
#ifdef BUILD_SCANNER
        (!all_children_done())
#else
        (!(all_children_done() && SCANNER.Done()))
#endif
      )
    {
#ifdef BUILD_SCANNER
       if(PIN_IsActionPending(tid))
        PIN_HANDLE_STUFF_AND_LOOP_BACK_TO_TOP();
      else
#endif
        goto make_slave;
    }

    /* We get here after Scan is complete! */
    LOG("All Children Finished\n");
    LOG_TIME();
    Release_Scanner_Master();

#ifdef BUILD_SCANNER
    Output_Scanner_Info_File(dep_index);
    PIN_MutexLock(Closure_Index_Mutex);
    (*CurrentClosureIndex) = (ADDRINT)-1;
    PIN_MutexUnlock(Closure_Index_Mutex);
    if(!All_Closures_Done())
      return;
    // else fall through...
#endif

    SCANNER.Fini();
    PIN_ExitApplication(0); // kill all!
  }
}

static inline VOID Start_Scan (const CONTEXT *ctxt,
                               ADDRINT* replace
#ifdef BUILD_SCANNER
                               , ADDRINT dep_index
#endif
                              )
{
  if(is_slave && !SCANNER.Is_Scanning()
#ifdef BUILD_SCANNER
     && Is_Current_DEP_Instruction(dep_index)
#endif
    )
  {

#if AGGRESSIVE_LOGGING >= 1
    LOG(format("Starting Scan(%d)\n") % PIN_GetPid());
#endif
    
#ifndef ONE_RESULT
    Saved_SP = PIN_GetContextReg(ctxt, REG_STACK_PTR);
#endif

    SCANNER.Start_Single_Scan(replace,
#ifdef BUILD_SCANNER
                              dep_index
#else
                              0
#endif
                             );
  }
}

/** Other Functions ;) **/
#if AGGRESSIVE_LOGGING > 1
static VOID ThreadStart(THREADID tid, CONTEXT* ctx, INT32 flags, VOID* v)
{
  INT pid = PIN_GetPid();
  LOG("-- THREAD " + decstr(pid) + "(" + decstr(tid) + ") START\n");
}

static VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
  INT pid = PIN_GetPid();
  LOG("-- THREAD " + decstr(pid) + "(" + decstr(tid) + ") FINISH\n");
}

static VOID ForkChild(THREADID tid, const CONTEXT* ctxt, VOID*)
{
  INT pid = PIN_GetPid();
  LOG("FORK in child - " + decstr(pid) + "(" + decstr(tid) + ")\n");
}

static inline VOID ForkBefore(THREADID tid, const CONTEXT* ctxt, VOID*)
{
  INT pid = PIN_GetPid();
  LOG("FORK before - " + decstr(pid) + "(" + decstr(tid) + ")\n");
}

static VOID Fini(INT32 code, VOID* v)
{
  LOG(format("*********** Fini %d****************\n") % PIN_GetPid());
}
#endif


static inline VOID
Abort_This_Scanning_Process() // Does NOT return!!!
{
#if AGGRESSIVE_LOGGING >= 1
  LOG(format("Killing (via Abort) scanning slave %d\n") % PIN_GetPid());
  LOG_TIME();
#endif
  SCANNER.Abort_Single_Scan();
  PIN_ExitApplication(0);
}

static inline VOID
End_This_Scanning_Process() // Does NOT return!!!
{
  SCANNER.Stop_Single_Scan();
#if AGGRESSIVE_LOGGING >= 1
  LOG(format("Killing scanning slave %d\n") % PIN_GetPid());
  LOG_TIME();
#else
# ifdef BUILD_SCANNER
  LOG(format("Killing scanning slave %d\n") % PIN_GetPid());
# endif
#endif

#ifdef STATISTICS
  if(max_threads_count == 1) {
    UINT32 totalsize = 0;
    std::map<ADDRINT, INT>::iterator iter;
    for (iter = addr2size.begin(); iter != addr2size.end(); ++iter) {
      totalsize += iter->second;
    }
    LOG(format("Scan size of slave %d : %d bytes\n") %  PIN_GetPid() % totalsize);
  }
#endif

  PIN_ExitApplication(0);
}

/*************************************************************************
 * Called as a replacement for the function which we get the
 * criteria from... Now it is time to see what poped out of the scanner! */
static inline VOID Handle_Crit_Target (const CONTEXT* ctxt,
                                       PIN_Critical_Funcs_Handler::Crit_Func* func)
{
  if(is_slave) {
#if AGGRESSIVE_LOGGING >= 1
    LOG("SCANNING OUTPUT REACHED\n");
#else
# ifdef BUILD_SCANNER
    LOG("SCANNING OUTPUT REACHED\n");
# endif
#endif
    void *ptr;
    ADDRINT len;
    Crit_Funcs.Handle(func, ctxt, ptr, len);
#if AGGRESSIVE_LOGGING > 1
    LOG(format("CRIT PTR 0x%lx LEN %d\n") % (ADDRINT)ptr % len);
#endif
    SCANNER.MemoryOutput(ptr, len);
    // We Have A WINNER!!
#ifdef ONE_RESULT
    End_This_Scanning_Process(); // Does NOT return!!!
#endif
  }
}

#ifndef ONE_RESULT
static inline VOID Handle_Slave_SP_Write(ADDRINT SP)
{
  if(SP > Saved_SP && is_slave) {
# if AGGRESSIVE_LOGGING >= 1
    LOG(format("[%d] Slave SP!\n") % PIN_GetPid());
# endif
    End_This_Scanning_Process(); // Does NOT return!!!
  }
}
#endif

static inline VOID Handle_Slave_Indirect_Branch(CONTEXT * ctxt, ADDRINT target) {
  if(__is_slave) {
    ADDRINT new_target;
    if(trans.Convert_Address(target, new_target)) {
#if AGGRESSIVE_LOGGING > 0
      LOG(format("WARN IND: %lx -> %lx\n") % target % new_target);
#endif
      if(new_target == target) return; // no need to patch! :)
      PIN_SetContextReg(ctxt, REG_INST_PTR, new_target);
      PIN_ExecuteAt(ctxt);
    }
  }
}

/*************************************************************************/
/* Called as a Handler for when program generates an exception.
 * If the scanner was running, see what poped out and kill the child! 
 * Otherwise, it is for the program to handle!                           */
static inline EXCEPT_HANDLING_RESULT HandleException(THREADID tid, EXCEPTION_INFO *except_info,
                                              PHYSICAL_CONTEXT *phys_ctxt, VOID *v)
{
  if(__is_slave) {
    /* This is most likely caused by a bad memory access in the scanner! */
#if AGGRESSIVE_LOGGING >= 1
    LOG(format("Scanner (%d) received INTERNAL Except:\n %s\n") 
         % PIN_GetPid()
         % PIN_ExceptionToString(except_info));
#endif
    Abort_This_Scanning_Process(); // Does NOT return!!!
  }
  LOG(format("Prog received Except: %s\n") % PIN_ExceptionToString(except_info));
  return EHR_UNHANDLED;
}

static inline BOOL HandleSignal(THREADID tid, INT32 sig, CONTEXT *from, BOOL hasHandler,
                         const EXCEPTION_INFO *except_info, VOID *v)
{
  if(sig == 11 && __is_slave) {
      // This is most likely caused by a bad memory access in the scanner!
#if AGGRESSIVE_LOGGING >= 1
      ADDRINT insaddr = PIN_GetContextReg(from, REG_INST_PTR);
      LOG(format("Scanner (%d) received signal: %d pc:%s\n")
           % PIN_GetPid() % sig % hexstr(insaddr));
      PIN_LockClient();
      IMG img = IMG_FindByAddress(insaddr);
      if(IMG_Valid(img))
        LOG(format("%lx + %s <%s>\n") 
            % (insaddr  - IMG_LowAddress(img)) 
            % IMG_Name(img) 
            % RTN_FindNameByAddress(insaddr));
      PIN_UnlockClient();
      LOG((except_info ? PIN_ExceptionToString(except_info) + "\n" : ""));
#endif
      Abort_This_Scanning_Process(); // Does NOT return!!!
  }
#if AGGRESSIVE_LOGGING >= 1
  LOG(format("(%d) SIGNAL (%d) %s\n") % PIN_GetPid() % sig 
        % (except_info ? PIN_ExceptionToString(except_info) : ""));
#endif

#ifdef BUILD_SCANNER
  if(sig == 17 && try_reclaim_all_possible_children()) return false; 
#endif

  if(Is_Scanning_Master_Alive()) return false;
  else return true;
}

/* ===================================================================== */
/* Instrument Functions                                                  */
/* ===================================================================== */
static inline VOID BL_Return_Const (CONTEXT* ctxt,
                                    ADDRINT ret_addr,
                                    ADDRINT ret_val)
{
  if(__is_slave) {
#if AGGRESSIVE_LOGGING >= 1
    LOG(format("(%d) Const: %llx<<%lld\n") 
         % PIN_GetPid() % ret_addr % ret_val);
#endif
   PIN_SetContextReg(ctxt, LEVEL_BASE::REG_STACK_PTR, 
     PIN_GetContextReg(ctxt, LEVEL_BASE::REG_STACK_PTR) + sizeof(ADDRINT));
   PIN_SetContextReg(ctxt, LEVEL_BASE::REG_RAX, ret_val);
   PIN_SetContextReg(ctxt, LEVEL_BASE::REG_INST_PTR, ret_addr);
   PIN_ExecuteAt(ctxt);
  }
}

static inline VOID BL_Kill_Slave(char* excuse)
{
 if(__is_slave) {
#if AGGRESSIVE_LOGGING >= 1
  LOG(format("(%d) Made Killer Call: %s\n") % PIN_GetPid() % excuse);
#endif
  Abort_This_Scanning_Process(); // Does NOT return!!!
 }
}

struct func{
  AFUNPTR fun_ptr;
  IARGLIST arg_list;
};
map<string, func> Blacklist;
static inline VOID Replace_Blacklist_Func(IMG img)
{
  for(SYM sym=IMG_RegsymHead(img); SYM_Valid(sym); sym=SYM_Next(sym))
  {
    map<string, func>::iterator it = Blacklist.find(SYM_Name(sym));
    if (it == Blacklist.end())
      continue;
    ADDRINT rtn_addr = IMG_LowAddress(img) + SYM_Value(sym);
    RTN rtn = RTN_FindByAddress(rtn_addr);
    if(!RTN_Valid(rtn) || SYM_IFunc(RTN_Sym(rtn)))
      continue;
    string rtn_name = RTN_Name(rtn);
    LOG(format(" Replace %s in %s : %s(%s)\n")
         % rtn_name % IMG_Name(img) % rtn_name 
         % hexstr(RTN_Address(rtn)));
    RTN_Open(rtn);
    if(it->second.fun_ptr == (AFUNPTR)BL_Return_Const)
    {
      RTN_InsertCall(rtn, IPOINT_BEFORE, it->second.fun_ptr,
                     IARG_CONTEXT, IARG_RETURN_IP, 
                     IARG_IARGLIST, it->second.arg_list, IARG_END);
    }
    else
    {
      RTN_InsertCall(rtn, IPOINT_BEFORE, it->second.fun_ptr,
                     IARG_IARGLIST, it->second.arg_list, IARG_END);
    }
    RTN_Close(rtn);
  }
}
const char poll_str[] = "Slaves cannot poll!";
const char asrt_str[] = "Slave failed assert!";
const char thrw_str[] = "Slave threw excep?";
const char frk_str[] = "Slaves cannot fork!";
static inline VOID Setup_Blacklist() {
#define BLACKLIST(name, funptr, ... ) \
  do { \
    struct func f = { (AFUNPTR)(funptr), IARGLIST_Alloc() }; \
    IARGLIST_AddArguments(f.arg_list, __VA_ARGS__, IARG_END); \
    Blacklist[(name)] = f; \
  } while(0)

  BLACKLIST("g_type_check_instance_is_a", BL_Return_Const, IARG_ADDRINT, 1);
  BLACKLIST("g_type_check_instance_cast", BL_Return_Const, IARG_FUNCARG_ENTRYPOINT_VALUE, 0);
  BLACKLIST("free", BL_Return_Const, IARG_REG_VALUE, LEVEL_BASE::REG_RAX); 
  BLACKLIST("seek", BL_Return_Const, IARG_FUNCARG_ENTRYPOINT_VALUE, 1);
  BLACKLIST("_ZN7QWidget4showEv", BL_Return_Const, IARG_REG_VALUE, LEVEL_BASE::REG_RAX);
  BLACKLIST("_ZN7QWidget7repaintEb", BL_Return_Const, IARG_REG_VALUE, LEVEL_BASE::REG_RAX);

//  BLACKLIST("poll", BL_Kill_Slave, IARG_PTR, poll_str);
  BLACKLIST("__assert_fail", BL_Kill_Slave, IARG_PTR, asrt_str);
  BLACKLIST("__cxa_throw", BL_Kill_Slave, IARG_PTR, thrw_str);
  BLACKLIST("fork", BL_Kill_Slave, IARG_PTR, frk_str);
#undef BLACKLIST
}

static inline VOID InstrumentINS(INS ins, VOID*);

static VOID InstrumentIMG(IMG img, VOID*)
{
  LOG(format("IMG 0x%09x - 0x%09x : %s\n")
          % IMG_LowAddress(img) % IMG_HighAddress(img) % IMG_Name(img));

  trans.Mark_IMG_Address(IMG_Name(img), IMG_LowAddress(img));
  
  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    LOG(format(" SEC 0x%09x - 0x%09x : %s\n")
          % SEC_Address(sec) % (SEC_Address(sec)+SEC_Size(sec)) % SEC_Name(sec));
  /*  for(RTN rtn= SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
      RTN_Open(rtn);
      for(INS ins= RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        InstrumentINS(ins, NULL);
      RTN_Close(rtn);
    } */
  }

  Replace_Blacklist_Func(img);  
  
#ifdef GDK_PIXBUF_OUTPUT
  RTN rtn = RTN_FindByName(img, "gdk_pixbuf_save_to_bufferv");
  if (RTN_Valid(rtn)) {
    Crit_Funcs.Init_GDK_Pixbuf_Output(RTN_Funptr(rtn));
  }
#endif

  if(IMG_IsMainExecutable(img)) {
    LOG("  main executable : " + IMG_Name(img) + "\n");
  }
}
static inline VOID InstrumentINS(INS ins, VOID*)
{
#define INS_InsertCallBefore(ins, funptr, ...) \
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)(funptr), __VA_ARGS__)
#define INS_InsertCallAfter(ins, funptr, ...) \
  do { \
    if (INS_HasFallThrough(ins)) \
      INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)(funptr), __VA_ARGS__); \
    if (INS_IsBranchOrCall(ins)) \
      INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)(funptr), __VA_ARGS__); \
  } while(0)
#ifdef STATISTICS
  INS_InsertCallBefore(ins, AFUNPTR(Call_On_Every_Instruction), IARG_ADDRINT,
                       INS_Address(ins), IARG_UINT32, INS_Size(ins), 
                       IARG_CALL_ORDER, CALL_ORDER_FIRST+1, IARG_END);
#endif

  IMG img = INS_Img(ins);
  if(!IMG_Valid(img)) return;

  ADDRINT ins_offset = INS_Address(ins) - IMG_LowAddress(img);

  if (INS_IsIndirectBranchOrCall(ins)) {
#if AGGRESSIVE_LOGGING > 0
    LOG(format("[%d] Replace IND CALL %lx %s\n")
         % PIN_GetPid() % ins_offset % IMG_Name(img));
#endif
    INS_InsertCallAfter (ins, AFUNPTR(Handle_Slave_Indirect_Branch),
                         IARG_CONTEXT,
                         IARG_BRANCH_TARGET_ADDR,
                         IARG_CALL_ORDER, CALL_ORDER_LAST,
                         IARG_END);
  }


  if(IsMainExecutable(img, INS_Rtn(ins))) {
    PIN_Critical_Funcs_Handler::Crit_Func* func =
                         Crit_Funcs.Lookup(ins_offset, IMG_Name(img));
    if(func != NULL) {
#if AGGRESSIVE_LOGGING > 1
      LOG(format("[%d] Replace %lx %s\n")
           % PIN_GetPid() % ins_offset % IMG_Name(img));
#endif
      INS_InsertCallBefore (ins, AFUNPTR(Handle_Crit_Target),
                            IARG_CONST_CONTEXT,
                            IARG_PTR, func,
                            IARG_CALL_ORDER, CALL_ORDER_FIRST,
                            IARG_END);
      return;
    }
  
#ifndef ONE_RESULT
    if (!INS_IsCall(ins) && INS_RegWContain(ins, REG_STACK_PTR)) {
# if AGGRESSIVE_LOGGING > 1
      LOG(format("[%d] Replace SP %lx %s\n")
           % PIN_GetPid() % ins_offset % IMG_Name(img));
# endif
      INS_InsertCallAfter (ins, AFUNPTR(Handle_Slave_SP_Write),
                           IARG_REG_VALUE, REG_STACK_PTR, 
                           IARG_CALL_ORDER, CALL_ORDER_FIRST,
                           IARG_END);
    }
#endif
  }

  if(__is_slave) return;

#ifdef BUILD_SCANNER
  for(ADDRINT i = 0; i < PossibleClosures.size(); i++)
  {
    ClosurePoint& Closure = PossibleClosures[i];
#endif
    if(Closure.offset == ins_offset && IMG_Name(img) == Closure.img_name)
    {
      const DEP& d = Closure.d;
      INS_InsertCallBefore (ins, (AFUNPTR)Setup_Scan,
                            IARG_CONST_CONTEXT,
                            IARG_INST_PTR, IARG_THREAD_ID,
#ifdef BUILD_SCANNER
                            IARG_ADDRINT, i,
#endif
                            IARG_CALL_ORDER, CALL_ORDER_FIRST + 10,
                            IARG_END);

      if (d.type == REG_DEP) {
        INS_InsertCallAfter (ins, (AFUNPTR)Start_Scan,
                             IARG_CONST_CONTEXT,
                             IARG_REG_REFERENCE, (REG)d.reg,
#ifdef BUILD_SCANNER
                             IARG_ADDRINT, i,
#endif
                             IARG_CALL_ORDER, CALL_ORDER_FIRST + 10,
                             IARG_END);
      }
      else {
        INS_InsertCallBefore (ins, (AFUNPTR)Start_Scan,
                              IARG_CONST_CONTEXT,
                              IARG_MEMORYREAD_EA,
#ifdef BUILD_SCANNER
                              IARG_ADDRINT, i,
#endif
                              IARG_CALL_ORDER, CALL_ORDER_FIRST + 20,
                              IARG_END);
      }
    }
#ifdef BUILD_SCANNER
  }
#endif

#undef INS_InsertCallBefore
#undef INS_InsertCallAfter
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */


static inline INT32 Usage()
{
#ifdef BUILD_SCANNER
  cerr << "\n ====BUILD SCANNER PHASE====" << endl;
#else
  cerr << "\n ====PRODUCTION SCANNER PHASE====" << endl;
#endif
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}


/* ===================================================================== */
/* Init, Fini, and Command Line Parsing                                  */
/* ===================================================================== */
static inline void *alloc_multiproc_shared_mem(ADDRINT size)
{
 return mmap(NULL, size, PROT_READ|PROT_WRITE,
             MAP_SHARED|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
}

static inline VOID Init()
{
  Scanner_Master_Pid = -1;

  slave_data_init(max_threads_count);
#ifdef BUILD_SCANNER
  CurrentClosureIndex = (ADDRINT*)alloc_multiproc_shared_mem(sizeof(UINT32));
  *CurrentClosureIndex = (ADDRINT)-1;
  Closure_Index_Mutex = (PIN_MUTEX*)alloc_multiproc_shared_mem(sizeof(PIN_MUTEX));
  PIN_MutexInit(Closure_Index_Mutex);
#endif
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

/* Command Line opts... */
KNOB<string> KnobMemImgFile(KNOB_MODE_WRITEONCE, "pintool",
    "mem", "", "Memory Img File");
KNOB<string> KnobMemInfoFile(KNOB_MODE_WRITEONCE, "pintool",
    "mem_info", "", "Memory Info File");
KNOB<string> KnobCriteriaTargetFunc(KNOB_MODE_WRITEONCE, "pintool",
    "t_func", "", "Criteria Target Function File");
#ifdef BUILD_SCANNER
KNOB<UINT32> KnobMaxPercent(KNOB_MODE_WRITEONCE, "pintool",
    "p", "10", "Max Percent for Guessing");
KNOB<string> KnobAnalysisDir(KNOB_MODE_WRITEONCE, "pintool",
    "build_scanner", "", "Build a Scanner Info file from this analysis directory");
#else
KNOB<UINT32> KnobMaxThreadCount(KNOB_MODE_WRITEONCE, "pintool",
    "j", "1", "Max Number of Threads");
KNOB<string> KnobScannerInfoFile(KNOB_MODE_WRITEONCE, "pintool",
    "scanner_info", "", "Scanner Info file to use for scanning memory img");
#endif
KNOB<UINT32> KnobGTKOutput(KNOB_MODE_WRITEONCE, "pintool",
    "use_gtk", "0", "Use GTK for graphical output");

int main(int argc, char* argv[])
{
  Setup_Blacklist();

  // Initialize pin
  if (PIN_Init(argc, argv)) return Usage();

  trans.Import(KnobMemInfoFile.Value());

#ifdef GTK_OUTPUT_ON
    LOG("Using GTK Output\n");
#endif

  if(SCANNER.Init(KnobMemImgFile.Value().c_str(),KnobMemInfoFile.Value()))
    return Usage();
  
  Crit_Funcs.Import(KnobCriteriaTargetFunc.Value());

  max_threads_count = 
#ifdef BUILD_SCANNER
                      1;
#else
# ifdef STATISTICS
                      1;
# else
#  if AGGRESSIVE_LOGGING > 1
                      1;
#  else
                      KnobMaxThreadCount.Value();
#  endif
# endif
#endif

#ifdef BUILD_SCANNER
  if(KnobAnalysisDir.Value() != "") {
    AnalysisDir = KnobAnalysisDir.Value();
    double percent = double(KnobMaxPercent.Value()) / 100.00;

    PossibleClosures = TryFindGuessFile(AnalysisDir);

    if(PossibleClosures.empty())
      PossibleClosures = Make_Guesses(AnalysisDir, &SCANNER, percent, trans);

    if(PossibleClosures.empty()) {
      puts("No Guesses Found!\n");
      return -1;
    }

    LOG(format("\n\n***********************\n\nTesting %ld Possible Closures\n")
          % PossibleClosures.size());
    for(ClosurePoint c: PossibleClosures) {
      LOG(format("%s\n") % c.ToString());
    }
    system("mkdir -p " NEW_SCANNER_INFO_DIR);
  
    OutputGuessFile(AnalysisDir, PossibleClosures);
  }
#else
  if(KnobScannerInfoFile.Value() != "")
  {
    FILE* scanner_info = fopen(KnobScannerInfoFile.Value().c_str(), "rt");
    if(scanner_info == NULL)
      return Usage();
    char line[1024];
    fgets(line, 1024, scanner_info);
    Closure = ClosurePoint(line);
    fclose(scanner_info);
    LOG(format("Closure: %s\n") % Closure.ToString());
  }
#endif
  else
    return Usage();

  PIN_InitSymbols();
  if(PIN_InitSymbolsAlt(IFUNC_SYMBOLS) != TRUE)
  { 
    LOG("Error Reading IFUNC Symbols?\n");
  }

  Init();

  // Register InstrumentINS to be called to instrument instructions
  IMG_AddInstrumentFunction(InstrumentIMG, 0);
  INS_AddInstrumentFunction(InstrumentINS, 0);

#if AGGRESSIVE_LOGGING > 1
  // Register Fini to be called when A TRACED PROCESS (hint: forking) exits
  PIN_AddFiniFunction(Fini, 0);

  PIN_AddThreadStartFunction(ThreadStart, 0);
  PIN_AddThreadFiniFunction(ThreadFini, 0);

  PIN_AddForkFunction(FPOINT_BEFORE, ForkBefore, 0);
  PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChild, 0);
#endif

  INT32 sigs[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 
                   13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                   23, 24, 25, 26, 27, 28, 29, 30, 31, 34,
                   35, 36, 37, 38, 39, 40,41,42,43,44,45,
                   46,47,48,49,50,51,52,53,54,55,56,57,58,
                   59,60,61,62,63,64};
  INT32 n_sigs = (sizeof(sigs) / sizeof(INT32));
  for(INT32 i = 0; i < n_sigs; i++)
    PIN_InterceptSignal(sigs[i], HandleSignal, 0);

  PIN_AddInternalExceptionHandler(HandleException, 0);  

  puts("Starting Application ... Please Begin Interaction\n");

#if AGGRESSIVE_LOGGING > 0
  puts("\n\nWARNING: DEBUG ON!\n\n");
#endif
#ifdef STATISTICS
  puts("\n\nWARNING: STATISTICS ON, SINGLE THREAD!\n\n");
#endif


#ifdef BUILD_SCANNER
  printf("Testing %ld Possible Closures - Check %s for current number\n\n", 
         PossibleClosures.size(), NEW_SCANNER_INFO_DIR);
#endif

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
