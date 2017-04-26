#ifndef _PIN_SCAN_SLAVES
#define _PIN_SCAN_SLAVES

#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <stdlib.h>

#include "pin.H"

#include "pin_forensix_scanner.h"

#include <sys/wait.h>

#define SLAVE_TIME_LIMIT (5) // in seconds

//#define SMART_BALANCE
#undef SMART_BALANCE


typedef struct {
  INT pid;
  time_t start_time;
} Slave_Proc_Info;

extern Slave_Proc_Info *Slave_PIDs;
extern UINT32 Slave_PIDs_Count;
extern UINT32 max_threads_count;
extern UINT32 current_max_threads_count;

#ifdef SMART_BALANCE
const int cpu_load = (int)((double)sysconf(_SC_NPROCESSORS_ONLN) * 1.5);
#endif

static inline void slave_data_init(UINT32 max_threads)
{
#ifdef SMART_BALANCE
  max_threads_count = 1000;
  current_max_threads_count = cpu_load * 2;
#else
  max_threads_count = max_threads;
  current_max_threads_count = max_threads_count;
#endif
  Slave_PIDs = new Slave_Proc_Info[max_threads_count];
  Slave_PIDs_Count = 0;
}

static inline void remove_slaves_between(UINT32 start, UINT32 end)
{
  memmove((void *)&(Slave_PIDs[start]), (void *)&(Slave_PIDs[end+1]),
   (((ADDRINT)&(Slave_PIDs[Slave_PIDs_Count-1])) - ((ADDRINT)&(Slave_PIDs[end]))));
  Slave_PIDs_Count-= ((end - start) + 1);
}

static inline BOOL try_reclaim_all_possible_children()
{
  int status;
  int pid, start = -1, end=-1;
  time_t now = time(NULL);

  for(UINT32 i = 0; i < Slave_PIDs_Count; i++)
  {
    status = 0;
    if(Slave_PIDs[i].start_time + (SLAVE_TIME_LIMIT) < now) 
    {
#if AGGRESSIVE_LOGGING >= 1
      LOG(format("Timeout Kill on %d\n") % Slave_PIDs[i].pid);
#endif
      kill(Slave_PIDs[i].pid, SIGKILL);
    }

    pid = waitpid(Slave_PIDs[i].pid, &status, WNOHANG);
    if((pid == Slave_PIDs[i].pid && (WIFEXITED(status) || WIFSIGNALED(status))) || // slave died 
       (pid == -1 && errno == ECHILD)) // The application reclaimed my slave!
    {
#if AGGRESSIVE_LOGGING > 1
      LOG(format("Reclaiming pid %d\n") % Slave_PIDs[i].pid);
#endif
      // so we should remove this guy.
      if(start == -1)
      {
        start = i;
      }
      end = i;
    }
    else
    {
      if(pid == -1)
        LOG(format("! waitpid (%d) error (%d): %s\n") % Slave_PIDs[i].pid % errno % strerror(errno));
      // we dont remove this guy, take care of the others...
      if(start != -1)
      {
        remove_slaves_between(start,end);
        start = -1;
      }
    }
  }
  if(start != -1)
    remove_slaves_between(start,end);
  return false;
}


static inline void add_slave_pid(INT PID) 
{
  time_t now = time(NULL);
  if(now == (time_t)-1)
    LOG(format("! time (%d) error (%d): %s\n") % PID % errno % strerror(errno));
  Slave_Proc_Info* s = &(Slave_PIDs[Slave_PIDs_Count]);
  s->pid = PID;
  s->start_time = now;
  Slave_PIDs_Count++;
#if AGGRESSIVE_LOGGING > 1
  LOG(format("(%d)New Slave - (%d)%d\n") % PIN_GetPid() % Slave_PIDs_Count % PID);
  for(UINT32 i = 0; i < Slave_PIDs_Count; i++) {
    LOG(format(" %d\n") % Slave_PIDs[i].pid);
  }
#endif
}

#ifdef SMART_BALANCE
double usage, usage_prev = 0;
#endif
static inline BOOL can_add_slaves()
{
#ifdef SMART_BALANCE
  if (getloadavg(&usage, 1) > 0) {
    if (usage != usage_prev) 
    {
      if (usage > (cpu_load+1) &&
          current_max_threads_count > 1)
        current_max_threads_count--;
      else if (usage < cpu_load &&
               current_max_threads_count < max_threads_count)
        current_max_threads_count++;
      usage_prev = usage;
    }
  }
#endif
  return (Slave_PIDs_Count < current_max_threads_count);
}

#define all_children_done() (Slave_PIDs_Count == 0)

#endif //_PIN_SCAN_SLAVES
