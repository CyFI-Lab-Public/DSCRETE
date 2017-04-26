#include "pin_forensix_slicing.h"
#include <vector>
#include <string>
#include <libgen.h>
#include "pin_slicing_model.h"
#include "pin.H"
#include "pin_helper.h"
#include <map>
#include "my_popen.h"
#include "pin_models.h"

#define DEBUG_SCRIPT 0

#define MODEL_MAKER_ENV_VAR "DYN_MODEL_MAKER_PATH"
#define SCRIPT_NAME "dynamic_model_maker_start.sh"
#define OUTPUT_SYMBOLS_ENV_VAR "OUTPUT_MODELS_PATH"
#define OUTPUT_SYMBOLS_NAME "output.symbols"

static inline string get_file_path(const char *env_name, const char *file_name)
{
  char *ret = getenv(env_name);
  if (ret == NULL) ret = dirname((char *)__FILE__);
  return string(ret) + "/"+string(file_name);
}


static inline map<string, BOOL> Import_Output_Symbols()
{ 
  /* format of output symbols file:
   *  func@lib.so - will also dump heap memory
   *  ! func@lib.so - will not
   */
  string filename = get_file_path(OUTPUT_SYMBOLS_ENV_VAR, OUTPUT_SYMBOLS_NAME);
  LOG(format("Importing Output Symbols: %s\n") % filename);
  FILE* f = fopen(filename.c_str(), "r");
  assert(f && "Cannot Open output.symbols");
   
  map<string, BOOL> ret;
#define BUF_SZ (4096)
  char output[BUF_SZ];
  memset(output, 0, BUF_SZ);

  while(fgets(output, BUF_SZ, f))
  {
    assert(strstr(strstr(output, "@lib"), ".so") != NULL &&
           "Incorrect output.symbols file!");
    register unsigned len = strlen(output) - 1;
    if(output[len] == '\n') { output[len] = '\0'; }
    BOOL no_heap_dump = (output[0] == '!' && output[1] == ' ');
    if(no_heap_dump) memmove(output, output + 2, len+1);
    ret.insert(pair<string, BOOL>(string(output), !no_heap_dump));
#if AGGRESSIVE_DEBUG > 0
    LOG(format("Output Symbol: %s (%s Heap)\n") % output % (no_heap_dump ? "No" : "Yes"));
#endif
    memset(output, 0, BUF_SZ);
  }

  fclose(f);
  return ret;
}

static inline string get_lib_name(const string& imgname)
{
  char libname[512];
  strcpy(libname, basename((char *)imgname.c_str()));
  *(strstr(libname, ".so")+3) = '\0';
  return libname;
}

static Pipes modeler = open_pipes(get_file_path(MODEL_MAKER_ENV_VAR, SCRIPT_NAME));

VOID ShutdownModels ()
{
  fprintf(modeler.input, "QUIT\n");
}

static inline Model_Info Pull_From_Script(const string& rtnname, const string& imgname)
{
#if AGGRESSIVE_DEBUG > 2 | DEBUG_SCRIPT == 1
  LOG(format(SCRIPT_NAME" %s@%s\n") % rtnname % imgname);
#endif  
  fprintf(modeler.input, "%s@%s\n", rtnname.c_str(), imgname.c_str());

  Model_Info m_i = Model_Info(rtnname, imgname);

#define BUF_SZ (4096)
  char output[BUF_SZ];
  fgets(output, BUF_SZ, modeler.output); // eat up echo line...
  memset(output, 0, BUF_SZ);
  // First Line: Either data or "Cannot find ..."
  fgets(output, BUF_SZ, modeler.output);
#if AGGRESSIVE_DEBUG > 2 | DEBUG_SCRIPT == 1
    LOG(format(SCRIPT_NAME" : %s\n") % output);
#endif
  m_i.found = ::strstr(output, "Cannot Find:") == NULL;
  if(!m_i.found) return m_i;
  
  m_i.found_name = m_i.name;

  // We must have found it! Pull in data line!
  uint8_t num_args;
  {
    char ret_char;
    uint8_t has_ellips;
    sscanf(output, "%c %hhu %hhu", &(ret_char), &(num_args), &(has_ellips));
    switch(ret_char) {
      case 'v': m_i.ret_type = Model_Info::Model_Arg::TYPE_NONE; break;
      case 'f': m_i.ret_type = Model_Info::Model_Arg::TYPE_FLOAT; break;
      case 'i': m_i.ret_type = Model_Info::Model_Arg::TYPE_INT; break;
      default: assert(false && "Invalid Ret Type!"); break;
    }
    m_i.has_ellips = has_ellips == 1;
  }

  // Now pull in Args!
  m_i.args = Model_Info::Model_Args(num_args);
  for(uint8_t i = 0; i < num_args; i++) {
    memset(output, 0, BUF_SZ);
    fgets(output, BUF_SZ, modeler.output);
#if AGGRESSIVE_DEBUG > 2 | DEBUG_SCRIPT == 1
      LOG(format(SCRIPT_NAME" : %s\n") % output);
#endif
    char name [1024];
    char type;
    sscanf(output, "%*u %c %s", &type, name);
    switch(type) {
      case 'f':
        m_i.args.new_arg(Model_Info::Model_Arg::TYPE_FLOAT, name);
        break;
      case 'i':
        m_i.args.new_arg(Model_Info::Model_Arg::TYPE_INT, name);
        break;
      default: assert(false && "Invalid ARG Type!"); break;
    }
  }

  assert(num_args == m_i.args.num_args());
#undef BUF_SZ
  return m_i;
}

static inline
Model_Info Find_Model_For(RTN rtn, const string& rtnname, ADDRINT rtn_offset,
                          IMG img, const string& imgname)
{
  Model_Info ret;
  BOOL sym_found = false;
  // First, try to find a symbol that works...
  for(SYM sym=IMG_RegsymHead(img); SYM_Valid(sym); sym=SYM_Next(sym))
  {
    if(SYM_Value(sym) == rtn_offset)
    {
      sym_found = true;
      ret = Pull_From_Script(SYM_Name(sym), imgname);
      if(ret.found) break;
    }
  }
  if(!sym_found)
  { // No symbol for that offset? Possible a callback...
    ret = Pull_From_Script(rtnname, imgname);
  }
  return ret;  
}

/* MUST BE RTN_Valid(rtn) && IMG_Valid(img)! */
static inline Model_Info& Lookup_Model_Info(RTN rtn, const string& rtnname,
                                            IMG img, const string& iname)
{
  static map<string, Model_Info> known_models;
  //  assert(RTN_Valid(rtn) && IMG_Valid(img));
  string imgname = get_lib_name(iname);

  /* Is cached? */
  string key = rtnname+"@"+imgname;
  map<string, Model_Info>::iterator it = known_models.find(key);
  if (it != known_models.end()) return it->second;

//TODO may need to handle IFUNCs

  ADDRINT rtn_offset = RTN_Address(rtn) - IMG_LowAddress(img);
  Model_Info m_i = Find_Model_For(rtn, rtnname, rtn_offset, img, imgname);
  string new_key = m_i.name+"@"+imgname;
  Model_Info& ret = 
    known_models.insert(std::pair<string, Model_Info>(new_key, m_i)).first->second;
  
  /* Force all symbols for this routine into cache */
  for(SYM sym=IMG_RegsymHead(img); SYM_Valid(sym); sym=SYM_Next(sym))
  {
    if(SYM_Value(sym) == rtn_offset)
    {
      m_i.name = SYM_Name(sym);
      new_key = m_i.name+"@"+imgname;
      Model_Info& added = known_models.insert(std::pair<string, Model_Info>(new_key, m_i)).first->second;
      if(new_key == key) { // try to return the actual one we search for :P
        ret = added;
      }
    }
  }

  return ret;
}

static Model_Info Junk_Model = Model_Info();
static inline Model_Info& New_Unknown_Model(const string& rtnname, const string& imgname)
{
  Junk_Model.name = rtnname;
  Junk_Model.img_name = imgname;
  return Junk_Model;
}

typedef enum {
    MODEL_REG_READ,
    MODEL_REG_WRITE
} OpType;
struct RegOp {
  ADDRINT model_instance;
  OpType type;
  REG reg;
  ADDRINT val;
  RegOp(ADDRINT i, OpType o, REG r, ADDRINT v) : model_instance(i), type(o), reg(r), val(v) {}
};
static vector<RegOp> Model_Reg_Ops;

static Called_Model Current_Model;
VOID Enter_Model(RTN rtn, const string& rtnname, IMG img, const string& imgname,
                 const CONTEXT* ctxt, INSDESC* caller)
{
  assert(!Current_Model.Is_Called());

  Model_Info& New_Model = (RTN_Valid(rtn) && IMG_Valid(img) && rtnname.at(0) != '.' ?
                           Lookup_Model_Info(rtn, rtnname, img, imgname)
                           : New_Unknown_Model(rtnname, imgname));

  Current_Model = New_Model.Call(ctxt, *caller, PIN_GetContextReg(ctxt, REG_RSP));

#if AGGRESSIVE_DEBUG > 0
  LOG(format("Call to model function %s @ %s from %lx:%ld\n") % 
      Current_Model.info->name % Current_Model.info->img_name % 
      Current_Model.caller.addr % Current_Model.caller.instance);
#endif
  for(int i = 0; i < Current_Model.info->args.num_int_regs(); i++) {
     REG r = REG_INT_PARAM(i);
     Model_Reg_Ops.push_back(RegOp(INS_model->instance, MODEL_REG_READ, r, PIN_GetContextReg(ctxt, r)));
  }
  for(int i = 0; i < Current_Model.info->args.num_float_regs(); i++) {
     REG r = REG_FLOAT_PARAM(i);
     PIN_REGISTER value;
     PIN_GetContextRegval(ctxt, r, (UINT8*)&value);
     Model_Reg_Ops.push_back(RegOp(INS_model->instance, MODEL_REG_READ, r, value.qword[0]));
  }
}


VOID Leave_Model(const CONTEXT* ctxt)
{
  assert(Current_Model.Is_Called());
  static map<string, BOOL> Output_Symbols = Import_Output_Symbols();
  ADDRINT ret_val;

  if(Current_Model.info->ret_type == Model_Info::Model_Arg::TYPE_INT)
  {
    ret_val = PIN_GetContextReg(ctxt, REG_RAX);
    Model_Reg_Ops.push_back(RegOp(INS_model->instance, MODEL_REG_WRITE,
                                  REG_RAX, ret_val));
  }
  else if (Current_Model.info->ret_type == Model_Info::Model_Arg::TYPE_FLOAT)
  {
    PIN_REGISTER value;
    PIN_GetContextRegval(ctxt, REG_XMM0, (UINT8*)&value);
    ret_val = value.qword[0];
    Model_Reg_Ops.push_back(RegOp(INS_model->instance, MODEL_REG_WRITE,
                                  REG_XMM0, ret_val));
  }
  else
  {
    ret_val = 0;
  }

  Perform_Cached_Model_RegOps();

#if AGGRESSIVE_DEBUG > 0
  LOG(format("Leave model function %s @ %s\n") % Current_Model.info->name % Current_Model.info->img_name);
#endif

  map<string, BOOL>::iterator it = 
      Output_Symbols.find(Current_Model.info->name+"@"+Current_Model.info->img_name);
  if(it != Output_Symbols.end())
    SLICE.Output(Current_Model, ret_val, it->second);

  Current_Model.Return();
}


BOOL Has_Cached_Model_RegOps()
{
  return Model_Reg_Ops.size() != 0;
}
VOID Clear_Cached_Model_RegOps()
{
  Model_Reg_Ops.clear();
}
VOID Perform_Cached_Model_RegOps()
{
  for(RegOp r : Model_Reg_Ops) { 
    if(r.model_instance == INS_model->instance) 
    {
      if(r.type == MODEL_REG_READ)
        __RegisterRead(INS_model, r.reg, r.val);
      else
        __RegisterWritten(INS_model, r.reg, r.val);
    }
    else
    {
      LOG(format("Warning: REG %s %s from wrong instance %ld != %ld\n")
            % (r.type == MODEL_REG_READ ? "READ" : "WRITE")
            % REG_StringShort((REG)r.reg)
            % r.model_instance % INS_model->instance);
    }
  }
  Clear_Cached_Model_RegOps();
}
