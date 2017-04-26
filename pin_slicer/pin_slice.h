#ifndef PIN_SLICE_H
#define PIN_SLICE_H


#include <map>
#include <vector>
#include <utility>

#include "pin_cfg.h"
#include "pin.H"
#include "pin_inst_descriptor.h"
#include "shadow_memory.h"
#include "analysis_datatypes.h"
#include "pin_models.h"

class _CDStack
{
  struct CDEntry : II {
    INSDESC* callsite = 0;
    UINT64 ipdom = 0;
    CDEntry() : II() {}
    CDEntry(const INSDESC& ins) : II(ins.addr, ins.instance) {}
  };

  vector<CDEntry> stack;
  PIN_CFG CFG;

public:
  typedef vector<CDEntry>::iterator iterator;

  VOID EnterInstruction(INSDESC* ins);
  VOID LeaveInstruction(INSDESC* ins);
  VOID EnterFunction(INSDESC* caller);
  VOID LeaveFunction();
  VOID Init();
  VOID Fini();
  II Top();
  ADDRINT size() { return stack.size(); }
  iterator begin() { return stack.begin(); }
  iterator end() { return stack.end(); }
};


class PIN_Slice
{
  // Data Dep. ** Make own object!!!
  ShadowMemory<II>::ShadowMemory64 memories;
  II registers[REG_LAST];

  // Control Dep.
//  _CDStack CDStack;

  // Current instruction tracking
  II ii;
  
  set<DEP> dep;

  map<ADDRINT,string> filenames;

  FILE* fpi = 0;
  FILE* fpd = 0;
  FILE* fpw = 0;
  FILE* fpr = 0;
  FILE* fpo = 0;
  UINT64 tracesize = 0;

  VOID Print_Reg_Params(const Model_Info::Model_Args&, FILE*, set<DEP>*);
public:

  VOID Init();
  VOID Fini();

  VOID EnterInstruction(INSDESC* ins);
  VOID LeaveInstruction(INSDESC* ins);

  VOID RegisterRead(ADDRINT reg, ADDRINT value);
  VOID RegisterWritten(ADDRINT reg);
  
  VOID MemoryRead(ADDRINT addr, ADDRINT size, ADDRINT value);
  VOID MemoryWritten(ADDRINT addr, ADDRINT size);

  VOID OnOpen(ADDRINT fd, const char* path);
  string Filename(ADDRINT fd);

  /* fcrit **called from models!!** */
  VOID Input(string hint);
  VOID Input(char* hint_buff);

  /* bcrit **called from models!!** */
  VOID Output(const Called_Model& model, ADDRINT ret_val, bool dump_heap);
  VOID Output(const Called_Model& model, ADDRINT ret_val);
};
#endif // PIN_SLICE_H
