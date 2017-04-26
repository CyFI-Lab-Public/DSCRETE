#ifndef PIN_HELPER_H
#define PIN_HELPER_H

#include <set>
#include <string>
#include <cstring>
#include "pin.H"
#include "output.h"
#include <cassert>

#define MAX_INT_REG_PARAMS 6
#define MAX_FLOAT_REG_PARAMS 8

static inline REG REG_INT_PARAM(int i)
{
  static REG regs[MAX_INT_REG_PARAMS] = 
    {LEVEL_BASE::REG_RDI, LEVEL_BASE::REG_RSI, LEVEL_BASE::REG_RDX,
     LEVEL_BASE::REG_RCX, LEVEL_BASE::REG_R8, LEVEL_BASE::REG_R9};

  assert (i < MAX_INT_REG_PARAMS);
  return regs[i];
}

static inline REG REG_FLOAT_PARAM(int i)
{
  static REG regs[MAX_FLOAT_REG_PARAMS] = 
    {LEVEL_BASE::REG_XMM0, LEVEL_BASE::REG_XMM1, LEVEL_BASE::REG_XMM2,
     LEVEL_BASE::REG_XMM3, LEVEL_BASE::REG_XMM4, LEVEL_BASE::REG_XMM5,
     LEVEL_BASE::REG_XMM6, LEVEL_BASE::REG_XMM7};
  
  assert (i < MAX_FLOAT_REG_PARAMS);
  return regs[i];
}

static inline ADDRINT REG_INT_PARAM_NUM(REG reg)
{
  switch(reg){
   case LEVEL_BASE::REG_RDI: return 0;
   case LEVEL_BASE::REG_RSI: return 1;
   case LEVEL_BASE::REG_RDX: return 2;
   case LEVEL_BASE::REG_RCX: return 3;
   case LEVEL_BASE::REG_R8:  return 4;
   case LEVEL_BASE::REG_R9:  return 5;
   default:
     assert(false && "Passed Incorrect Reg to REG_INT_PARAM_NUM");
     return 0; // will not reach
  }
}

static inline ADDRINT REG_FLOAT_PARAM_NUM(REG reg)
{
  switch(reg){
   case LEVEL_BASE::REG_XMM0: return 0;
   case LEVEL_BASE::REG_XMM1: return 1;
   case LEVEL_BASE::REG_XMM2: return 2;
   case LEVEL_BASE::REG_XMM3: return 3;
   case LEVEL_BASE::REG_XMM4: return 4;
   case LEVEL_BASE::REG_XMM5: return 5;
   case LEVEL_BASE::REG_XMM6: return 6;
   case LEVEL_BASE::REG_XMM7: return 7;
   default:
     assert(false && "Passed Incorrect Reg to REG_FLOAT_PARAM_NUM");
     return 0; // will not reach
  }
}

static inline UINT64 PIN_ReadValue(ADDRINT ptr, UINT32 bytes)
{
  UINT64 v = 0;
  assert (bytes <= sizeof(v));
  PIN_SafeCopy(&v, (const VOID*)ptr, bytes);
  return v;
}

#define __STACK_PARAM(WHERE, offset) \
  static inline ADDRINT \
  WHERE ## _STACK_PARAM (int arg_num, ADDRINT sp) { \
    return sp + (arg_num * sizeof(ADDRINT)) + (offset); \
  }

/* BEFORE_CALL_STACK_PARAM(int arg_number, ADDRINT sp) */ __STACK_PARAM(BEFORE_CALL, 0);
/* AFTER_CALL_STACK_PARAM(int arg_number, ADDRINT sp) */  __STACK_PARAM(AFTER_CALL, sizeof(ADDRINT));

struct STACK_RESTORE {
  ADDRINT addr;
  ADDRINT* vals;
  uint8_t len;
  STACK_RESTORE(ADDRINT a, uint8_t l)
  {
    addr = a;
    len = l;
    vals = new ADDRINT[len];
    PIN_SafeCopy(vals, (ADDRINT*)addr, len);
    LOG("IN:\n");
    for (ADDRINT*s = ((ADDRINT*)addr)- 1; s <= (ADDRINT*)(addr + len); s++) LOG(format("S: %llu\n") % *s);
  }
  ~STACK_RESTORE()
  {
    LOG("OUT B:\n");
    for (ADDRINT*s = ((ADDRINT*)addr)- 1; s <= (ADDRINT*)(addr + len); s++) LOG(format("S: %llu\n") % *s);
    PIN_SafeCopy((ADDRINT*)addr, vals, len);
    LOG("OUT A:\n");
    for (ADDRINT*s = ((ADDRINT*)addr)- 1; s <= (ADDRINT*)(addr + len); s++) LOG(format("S: %llu\n") % *s);
    delete[] vals;
  }
};

/* ASSUMES THE RETURN ADDRESS IS ON *NOT* THE STACK! */
static inline STACK_RESTORE* Push_Int_Arg(CONTEXT *ctxt, uint8_t arg_number, ADDRINT val)
{
  STACK_RESTORE* ret;
  if(arg_number < MAX_INT_REG_PARAMS) {
    REG r = REG_INT_PARAM(arg_number);
    ret = Push_Int_Arg(ctxt, arg_number + 1, PIN_GetContextReg(ctxt, r));
    PIN_SetContextReg(ctxt, r, val);
  } else { // put it on the stack!
    ADDRINT* sp = (ADDRINT*)PIN_GetContextReg(ctxt, REG_STACK_PTR);
    ADDRINT* new_sp = sp - 1;
    uint8_t target_stack_num = (arg_number - MAX_INT_REG_PARAMS);
    ADDRINT* target_stack_addr = (ADDRINT*)BEFORE_CALL_STACK_PARAM(target_stack_num, (ADDRINT)new_sp);
    uint8_t copy_len = sizeof(ADDRINT) * (target_stack_num);
    LOG(format("=%llx==%llx==%llx\n") % sp % new_sp % target_stack_addr);
    for (ADDRINT*s = sp-3; s <= sp+10; s++) LOG(format("S: %llu\n") % *s);
    if(copy_len == 0)
      ret = NULL;
    else {
      // push down all args between you and sp
      ret = new STACK_RESTORE((ADDRINT)sp, copy_len);
      PIN_SafeCopy(new_sp, sp, copy_len);
    }
    LOG("--\n");
    for (ADDRINT*s = new_sp-2; s <= sp+10; s++) LOG(format("S: %llu\n") % *s);
    PIN_SafeCopy(target_stack_addr, &val, sizeof(ADDRINT));
    LOG("----\n");
    for (ADDRINT*s = new_sp-2; s <= sp+10; s++) LOG(format("S: %llu\n") % *s);
   // PIN_SetContextReg(ctxt, REG_STACK_PTR, (ADDRINT)new_sp);
  }
  return ret;
}

static inline void Fix_Stack(STACK_RESTORE* s) { if(s!=NULL) delete s; }

static inline BOOL IMG_IsLibLinux(IMG img)
{
  return IMG_Valid(img) && ::strstr(IMG_Name(img).c_str(), "ld-linux-x86-64.so.2") != NULL;
}

static inline BOOL IMG_IsLibC(IMG img)
{
  return IMG_Valid(img) && ::strstr(IMG_Name(img).c_str(), "libc.so") != NULL;
}

static inline IMG INS_Img(INS ins)
{
  if (!INS_Valid(ins))
    return IMG_Invalid();

  RTN rtn = INS_Rtn(ins);
  if (RTN_Valid(rtn))
    return SEC_Img(RTN_Sec(rtn));

  PIN_LockClient();
  IMG img = IMG_FindByAddress(INS_Address(ins));
  PIN_UnlockClient();
  return img;
}

extern set<string> _whitelist_;
static inline bool IMG_IsWhitelisted(IMG img)
{
  if (!IMG_Valid(img)) return false;

  for(string s : _whitelist_)
  {
    if(::strstr(IMG_Name(img).c_str(), s.c_str()) != NULL)
        return true;
  }
  return false;
}

extern set<string> _blacklist_;
static inline bool RTN_IsBlacklisted(RTN rtn)
{
  if (!RTN_Valid(rtn)) return false;
  string name = RTN_Name(rtn);
  if (_blacklist_.find(name) != _blacklist_.end()) return true;
  return false;
}

/* CALL THIS ONE ONLY TO TEST! DO NOT DO THE TESTING ON YOUR OWN!!! */
static inline BOOL IsMainExecutable(IMG img, RTN rtn)
{
  return IMG_Valid(img) && (IMG_IsMainExecutable(img) || IMG_IsWhitelisted(img)) && !RTN_IsBlacklisted(rtn);
}

static inline BOOL INS_IsMainExecutable(INS ins)
{
  return IsMainExecutable(INS_Img(ins), INS_Rtn(ins));
}

static inline BOOL ADDR_IsMainExecutable(ADDRINT pc)
{
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(pc);
    IMG img = IMG_FindByAddress(pc);
    PIN_UnlockClient();
    return IsMainExecutable(img, rtn);
}

static inline string IMG_FindNameByAddress(ADDRINT addr)
{
  PIN_LockClient();
  IMG img = IMG_FindByAddress(addr);
  PIN_UnlockClient();
  return (IMG_Valid(img) ? IMG_Name(img) : "");
}

static inline string Space(ADDRINT n)
{
  return string(n, ' ');
}

static inline char ToPrintableChar(char c)
{
  return ::isprint(c) ? c : '.';
}

static inline string ToPrintableString(const void* buf, ADDRINT len)
{
  string s;
  const char* p = (const char*)buf;
  for (ADDRINT i = 0; i < len; ++i, ++p)
    s += ToPrintableChar(*p);
  return s;
}
#endif // PIN_HELPER_H
