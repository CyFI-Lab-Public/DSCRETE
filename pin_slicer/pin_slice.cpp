
#include "pin.H"

#include <utility>
#include <cstring>
#include "pin_slice.h"
#include "pin_helper.h"
#include "pin_forensix_slicing.h"
#include "forensix_slicing_constants.h"
#include "pin_cfg.h"
#include "pin_inst_descriptor.h"
#include "analysis_datatypes.h"
#include "readwrite.h"
#include "pin_slicing_model.h"
#undef NDEBUG
#include <cassert>

VOID
_CDStack::EnterFunction(INSDESC* caller)
{
  if (!CFG.IsValid()) { return; }
  
  if (!stack.empty() && caller) {
    ADDRINT a = stack.back().addr;
    assert (a == caller->addr); // ensure assert works ...
    assert (stack.back().instance == caller->instance);
  }

  CDEntry e;
  if (caller) { e = *caller; }
  e.callsite = caller;
  e.ipdom = 0;

  stack.push_back(e);
}

VOID
_CDStack::LeaveFunction()
{
  if (!CFG.IsValid()) { return; }

  assert (!stack.empty());
  assert (stack.back().ipdom == 0);

  stack.pop_back();
}

VOID
_CDStack::EnterInstruction(INSDESC* ins)
{
  CFG.EnterInstruction(ins);

  if (!CFG.IsValid()) { return; }

  while (!stack.empty() && stack.back().ipdom == ins->addr) {
    stack.pop_back();
  }
}

VOID
_CDStack::LeaveInstruction(INSDESC* ins)
{
  if (!CFG.IsValid()) { return; }
  
  if (ins != INS_exit && ins != INS_entry) {
    CDEntry e = *ins;
    e.callsite = 0;
    CFG::Node& n = CFG.Find(ins);

    assert (n.ipdom);

    e.ipdom = n.ipdom->addr;

    assert (e.ipdom);

    stack.push_back(e);
  }
}

VOID
_CDStack::Init()
{
  CFG.Import(CFG_FILE_NAME);
  assert(INS_entry && "Must be called after init'ing INS_entry!");
  ADDRINT a = INS_entry->addr;
  assert(a && "Must be called after init'ing INS_entry!");
  CFG.EnterInstruction(INS_entry);
}

VOID
_CDStack::Fini()
{
  CFG.EnterInstruction(INS_exit);
  LOG("CFG Export\n");
  CFG.Export(CFG_FILE_NAME);
  LOG(format("CDStack is %s VALID\n") % (CFG.IsValid() ? "" : "NOT"));
}

II
_CDStack::Top()
{
  if (stack.empty()) {
    return II();
  }
  return stack.back();
}

VOID
PIN_Slice::Init()
{
  fpi = fopen("__trace_i.out", "wb");
  fpd = fopen("__trace_d.out", "wb");
  fpw = fopen("__write.out",   "wt");
  fpr = fopen("__read.out",    "wt");
  fpo = fopen("__open.out",    "wt");

  system((format("mkdir -p %s") % HEAP_DUMP_DIR).str().c_str());
  system((format("rm -rf %s/heap*.dump") % HEAP_DUMP_DIR).str().c_str());

  tracesize = 0;
  WRITE<UINT64>(fpi, tracesize);

  //CDStack.Init();
}

VOID PIN_Slice::Fini()
{
  rewind(fpi);
  WRITE<UINT64>(fpi, tracesize);

  //CDStack.Fini();

#define f_and_c(fp) \
  do{ \
    fflush(fp); \
    fclose(fp); \
  } while (0)

  f_and_c(fpi);
  f_and_c(fpd);
  f_and_c(fpw);
  f_and_c(fpr);
  f_and_c(fpo);
#undef f_and_c
}

VOID PIN_Slice::EnterInstruction(INSDESC* ins)
{
  ii = II(ins->addr, ins->instance);

  dep.clear();

  //if(ins != INS_model && ins != INS_entry && ins != INS_exit)
  //  CDStack.EnterInstruction(ins);

//  DEP d = { II() /*CDStack.Top()*/, CONTROL_DEP, 0, {0} };
//  dep.insert(d);
}

VOID PIN_Slice::LeaveInstruction(INSDESC* ins)
{
  ++tracesize;

  WRITE<UINT64>(fpi, ii.addr);
  WRITE<UINT64>(fpi, ii.instance);
  WRITE<UINT64>(fpi, ftell(fpd));
  fflush(fpi);

  for (set<DEP>::iterator p = dep.begin(); p != dep.end(); p++) {
    if (p->ii.addr == 0) dep.erase(p);
  }

  /* OUTPUT */
  WRITE<UINT64>(fpd, dep.size());

  for (set<DEP>::iterator p = dep.begin(); p != dep.end(); p++) {
    WRITE<DEP>(fpd, *p);
  }
  fflush(fpd);

  dep.clear();

  //if(ins != INS_model && ins != INS_entry && ins != INS_exit)
  //  CDStack.LeaveInstruction(ins);
}

VOID
PIN_Slice::RegisterRead(ADDRINT reg, ADDRINT value)
{
  switch (reg) {
  case REG_INVALID_:  case REG_INST_PTR:
  case REG_STACK_PTR: case REG_GBP:
    return;
  default:
    break;
  }
  II& r = registers[reg];
  if (r == ii || r.addr == 0) return;

  DEP d = { r, REG_DEP, value, {reg} };
  dep.insert(d);
}

VOID
PIN_Slice::RegisterWritten(ADDRINT reg)
{
  switch (reg) {
  case REG_INVALID_:  case REG_INST_PTR:
  case REG_STACK_PTR: case REG_GBP:
    return;
  default:
    break;
  }

  registers[reg] = ii;
}

VOID
PIN_Slice::MemoryRead(ADDRINT addr, ADDRINT size, ADDRINT value)
{
  assert (size <= sizeof(ADDRINT));

  DEP d;
  for (ADDRINT i = addr; i < addr + size; i++) {
    II m;
    if(!memories.get(i, m)) continue;
    if(m == ii || m.addr == 0) continue;
    /* LOG
    if (ii.addr == INS_model->addr) {
      LOG(format("    READ: ADDR %lx\n") % addr);
    }
    */

    d.ii = m;
    d.type = MEM_DEP;
    d.value = value;
    d.addr = addr;
    dep.insert(d);
  }
}

VOID
PIN_Slice::MemoryWritten(ADDRINT addr, ADDRINT size)
{
  assert (size <= sizeof(ADDRINT));
  
  for (ADDRINT i = addr; i < addr + size; i++) {
    memories.set(i, ii);
  }
}

VOID
PIN_Slice::OnOpen(ADDRINT fd, const char* path)
{
  assert(ii.addr == INS_model->addr);
  // Output and Input can ony be called from models!

  fprintf (fpo, "=================================================\n");
  fprintf (fpo, "fd: %ld, filename: %s\n", fd, path);
  fprintf (fpo, "\n");
  fprintf (fpo, "%lx %lu\n", ii.addr, ii.instance);

  filenames[fd] = path;
}

string
PIN_Slice::Filename(ADDRINT fd)
{   
    if (filenames.find(fd) != filenames.end())
        return filenames[fd];
    else
        return "";
}

static inline void dump_memory(string&, string&);

VOID
PIN_Slice::Output(const Called_Model& model, ADDRINT ret_val)
{
  Output(model, ret_val, true);
}

VOID
PIN_Slice::Print_Reg_Params(const Model_Info::Model_Args& model_args,
                            FILE* fp, set<DEP>* already_printed)
{
  class DEP_Chain {
    DEP source;
    vector<DEP_Chain*> points_to;
  public:
    DEP_Chain(DEP s) {source = s;}

    inline DEP& get_source() {return source;}
    
    inline bool check_and_add_ref(const DEP& d)
    {
      #define T 16 //Missing Bits Threshold!
      if(source.value - T <= d.addr && d.addr <= source.value + T) {
        points_to.push_back(new DEP_Chain(d));
        return true;
      }
      for(DEP_Chain* p : points_to) {
        DEP& ps = p->get_source();
        if(ps.addr - T <= d.addr && d.addr <= ps.addr + T) {
          points_to.push_back(new DEP_Chain(d));
          return true;
        }
      }
      for(DEP_Chain* p : points_to) {
        if(p->check_and_add_ref(d))
          return true;
      }
      return false;
      #undef T
    }

    inline string to_string()
    {
      string ret = DEPtoString(source) + "\n";

      for(DEP_Chain* p : points_to) {
        ret += p->to_string();
      }
      return ret;
    }
  };

  vector<pair<DEP_Chain*, uint8_t>> args;
#define ADD_DEP_TO_ARGS_IF(dep_type, dep_field, val, i) \
  for (set<DEP>::iterator p = dep.begin(); p != dep.end(); p++) { \
    if (p->type == (dep_type) && p->dep_field == (val)) { \
      args.push_back(pair<DEP_Chain*, uint8_t>(new DEP_Chain(*p), i)); \
      already_printed->insert(*p); \
      dep.erase(p); \
      break; \
    } \
  } 

  // INT ARGS...
  for(unsigned i = 0; i < model_args.num_args(); i++) {
    const Model_Info::Model_Arg& a = model_args.get(i);
    if (a.type == Model_Info::Model_Arg::TYPE_FLOAT) continue;
    if (a.loc == Model_Info::Model_Arg::ARG_REG) {
      ADD_DEP_TO_ARGS_IF(REG_DEP, reg, a.reg, i);
    } else {
      ADD_DEP_TO_ARGS_IF(MEM_DEP, addr, a.stack_addr, i);
    }
  }

  // Pointed too deps
  bool all_added = false;
  while(!all_added) {
    all_added = true;
    for (set<DEP>::iterator p = dep.begin(); p != dep.end();)
    {
      bool added_flag = false;
      for(const pair<DEP_Chain*, uint8_t>& a : args)
      {
        DEP_Chain* r = a.first;
        if(r->check_and_add_ref(*p)) {
          all_added = false;
          already_printed->insert(*p); 
          dep.erase(p++);
          added_flag = true;
          break;
        }
      }
      if(!added_flag)
       p++;
    }
  }

  // FP ARGS... 
  for(unsigned i = 0; i < model_args.num_args(); i++) {
    const Model_Info::Model_Arg& a = model_args.get(i);
    if (a.type == Model_Info::Model_Arg::TYPE_INT) continue;
    if (a.loc == Model_Info::Model_Arg::ARG_REG) {
      ADD_DEP_TO_ARGS_IF(REG_DEP, reg, a.reg, i);
    } else {
      ADD_DEP_TO_ARGS_IF(MEM_DEP, addr, a.stack_addr, i);
    }
  }

  for(const pair<DEP_Chain*, uint8_t>& a : args)
  {
    assert(a.second < model_args.num_args());
    fprintf (fp, "ARG %d %s", a.second, a.first->to_string().c_str());
  }
#undef ADD_DEP_TO_ARGS_IF
}


VOID
PIN_Slice::Output(const Called_Model& model, ADDRINT ret_val, bool dump_heap)
{
  assert(ii.addr == INS_model->addr);
  // Output and Input can only be called from models!

#ifdef HEAP_DUMP_AT_SLICE_OUTPUT
  static unsigned long heap_dump_count = 0;
  string heap_info_filename, heap_dump_filename;
  if(dump_heap) {
    heap_info_filename = (format("%s/heap%d.info") % HEAP_DUMP_DIR % ++heap_dump_count).str();
    heap_dump_filename = (format("%s/heap%d.dump") % HEAP_DUMP_DIR % heap_dump_count).str();
  }
#endif

  fprintf (fpw, "=================================================\n");
  fprintf (fpw, "Routine: %s | Img: %s\n", model.info->name.c_str(), model.info->img_name.c_str());
  fprintf (fpw, "Address: %lx | Inst: %ld\n", model.caller.addr, model.caller.instance);
#ifdef HEAP_DUMP_AT_SLICE_OUTPUT
  if(dump_heap) {
    fprintf (fpw, "Info File: %s | Dump File: %s\n",
                  heap_info_filename.c_str(), heap_dump_filename.c_str());
  }
#endif
  LOG(format("WRITE %s @ %s\n") % model.info->name.c_str() % model.info->img_name.c_str());
  
  if(model.info->ret_type != Model_Info::Model_Arg::TYPE_NONE)
     fprintf (fpw, "RET 0x%lx\n", ret_val);

  set<DEP> * already_printed = new set<DEP>;
  Print_Reg_Params(model.info->args, fpw, already_printed);
 
  // print the rest...
  fputs("=== Others\n", fpw);
  for (set<DEP>::iterator p = dep.begin(); p != dep.end(); p++) {
    if (p->ii.addr) {
      fprintf (fpw, "%s\n", DEPtoString(*p).c_str());
    }
  }

  for (set<DEP>::iterator p = already_printed->begin(); p != already_printed->end(); p++) {
    dep.insert(*p);
  }
  delete already_printed;
#ifdef HEAP_DUMP_AT_SLICE_OUTPUT
  if(dump_heap)
    ::dump_memory(heap_info_filename, heap_dump_filename);
#endif
}

VOID
PIN_Slice::Input(string hint)
{
  assert(ii.addr == INS_model->addr);
  // Output and Input can only be called from models!
  
  fprintf (fpr, "=================================================\n");
  fprintf (fpr, "%s\n", hint.c_str());

  LOG("READ " + hint  + "\n");

  fprintf (fpr, "%lx %lu\n", ii.addr, ii.instance);
}

VOID
PIN_Slice::Input(char* hint_buff)
{
  string s = hint_buff;
  Input(s);
}

static inline void dump_memory(string& heap_info_filename, string& heap_dump_filename)
{
  FILE* dump_file = fopen(heap_dump_filename.c_str(), "wb");
  assert(dump_file && "Error opening heap dump file!");
  FILE* info_file = fopen(heap_info_filename.c_str(), "wt");
  assert(dump_file && "Error opening heap dump file!");

  FILE* in_map = fopen((format("/proc/%d/maps") % PIN_GetPid()).str().c_str(), "r");
#define BUFFER_SZ (1024)
  char line[BUFFER_SZ];
  memset(line, 0, BUFFER_SZ);
  while(fgets(line, BUFFER_SZ, in_map) != NULL)
  {
    LOG(format("%s\n") % line);

    //if(strstr(line, "heap") != NULL || strstr(line, "stack") != NULL)
//    if((strstr(line, "rw-") != NULL || strstr(line, "rwx") != NULL )&&
//       strstr(line, "pin") == NULL && strstr(line, "lib") == NULL)
    {
      ADDRINT start = 0, end = 0;
      char name[BUFFER_SZ];
      memset(name, 0, BUFFER_SZ);

      sscanf(line, "%lx-%lx %*s %*x %*s %*s %s\n", &start, &end, name);

      if(strlen(name) == 0) strcpy(name, "[?]");
      assert(start != 0 && end != 0);

      fprintf(info_file, "%s\t%lx->%lu->%lx\n", name, start, end-start, ftell(dump_file));
      fwrite((void *)start, 1, end-start, dump_file);
    }
    memset(line, 0, BUFFER_SZ);
  }

  int ret = fclose(in_map);
  assert(ret == 0 && "Problem closing /proc/pid/maps file?");
  ret = fclose(dump_file);
  assert(ret == 0 && "Problem closing dump file?");
  ret = fclose(info_file);
  assert(ret == 0 && "Problem closing info file?");
#undef BUFFER_SZ
  return;
}

