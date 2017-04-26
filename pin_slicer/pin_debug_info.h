#ifndef PIN_DEBUG_INFO_H
#define PIN_DEBUG_INFO_H

#include "pin.H"

#include <string>

#include "debug_info.h"
#include "output.h"

class PIN_DebugInfoProducer: public DebugInfo
{
public:
    VOID Add(INS ins);
    VOID Add(RTN rtn);
    VOID Add(ADDRINT pc, RTN rtn);
    VOID AddFake(ADDRINT addr, const std::string& rtn_name);
    VOID AddModel(ADDRINT instance, INSDESC& called_from, 
		  const string& model_string_id);
};

VOID 
PIN_DebugInfoProducer::AddModel(ADDRINT instance, INSDESC& called_from,
                                const string& model_string_id)
{
  const DBG& called_from_dbg = get(called_from.addr, 0);
  INT32 line;
  string filename;
  PIN_LockClient();
  PIN_GetSourceLocation(called_from.addr, 0, &(line), &(filename));
  PIN_UnlockClient();
  _dbg[II(MODEL_INST_ADDR, instance)] = 
    DBG(MODEL_INST_ADDR, instance, called_from_dbg.rtn, called_from_dbg.rtnid,
        line, model_string_id, "", filename);
}

VOID
PIN_DebugInfoProducer::AddFake(ADDRINT addr, const std::string& rtn_name)
{
  _dbg[II(addr, 0)] =
    DBG(addr, 0, addr, addr, 0, rtn_name.c_str(), "", "");
}

VOID
PIN_DebugInfoProducer::Add(INS ins)
{
  ADDRINT pc = INS_Address(ins);
  RTN rtn = INS_Rtn(ins);
  INT32 line;
  string filename;
  PIN_GetSourceLocation(pc, 0, &(line), &(filename));
  _dbg[II(pc, 0)] = 
    DBG(pc, 0, RTN_Address(rtn), RTN_Id(rtn), line, RTN_Name(rtn).c_str(),
         INS_Disassemble(ins).c_str(), filename);
}

VOID
PIN_DebugInfoProducer::Add(ADDRINT pc, RTN rtn)
{
  if(!RTN_Valid(rtn)) {return;}
  INT32 line;
  string filename;
  PIN_GetSourceLocation(pc, 0, &(line), &(filename));
  _dbg[II(pc, 0)] = 
    DBG(pc, 0, RTN_Address(rtn), RTN_Id(rtn), line, RTN_Name(rtn).c_str(),
        "", filename);
}

VOID
PIN_DebugInfoProducer::Add(RTN rtn)
{
  ADDRINT pc = (ADDRINT)RTN_Id(rtn);
  _dbg[II(pc, 0)] = 
    DBG(pc, 0, RTN_Address(rtn), RTN_Id(rtn), 0,
         RTN_Name(rtn).c_str(), "", "");
}

#endif // PIN_DEBUG_INFO_H 
