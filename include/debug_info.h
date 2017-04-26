#ifndef DEBUG_INFO_H
#define DEBUG_INFO_H


#include <cassert>

#include "btree/btree_map.h"
#include "analysis_datatypes.h"
#include "pin_types.h"
#include "output.h"
#include <string>

class DBG
{
public:
    ADDRINT addr;
    ADDRINT instance; // only used for model instructions
    ADDRINT rtn;
    ADDRINT rtnid;
    ADDRINT line;
    std::string rtnname;
    std::string assembly;
    std::string filename;
    DBG () { DBG(0,0,0,0,0, "", "", ""); }
    DBG (ADDRINT a, ADDRINT i, ADDRINT r, ADDRINT rid,
        ADDRINT l, const std::string& rname, const std::string& asmbly,
        const std::string& fname)
    {
      addr = a;
      instance = i;
      rtn = r;
      rtnid = rid;
      line = l;
      rtnname = (rname == "" ? "No_RTN" : rname);
      assembly = (asmbly == "" ? "0" : asmbly);
      filename = (fname == "" ? "No_File_Info" : fname);
    }
};

class DebugInfo
{
public:
    VOID Export(const std::string& filename);
    VOID Import(const std::string& filename);

    const DBG& get(ADDRINT addr, ADDRINT instance) {
        assert(instance == 0 || addr == MODEL_INST_ADDR);
        auto I = _dbg.find(II(addr, instance));
        assert (I != _dbg.end());
        return I->second;
    }    
    
protected:
    btree::btree_map<II, DBG> _dbg;
};

VOID
DebugInfo::Import(const std::string& filename)
{
  FILE* fp = fopen(filename.c_str(), "r");

  if (!fp) {
    LOG(format("WARNING: No debug file (%s) found!\n") % filename.c_str());
    return;
  }
  
  char buffer[4096];
  int cnt = 0;
  while (fgets(buffer, 4096, fp)) {
    ++cnt;

    char rtnname[2048];
    memset(rtnname, 0, 2048);
    char* assembly;
    char* filename;
    ADDRINT addr, inst, rtn, rtnid, line;

    assembly = strtok(buffer, "\""); 
    assert (assembly);
    sscanf(assembly, "%lx %lx %lx %lu %s %lu",
              &addr, &inst, &rtn, &rtnid, rtnname, &line);
    assert(inst == 0 || addr == MODEL_INST_ADDR);

    assembly = strtok(NULL, "\"");
    assert (assembly);

    filename = strtok(NULL, "\n");
    assert (filename);

    _dbg[II(addr, inst)] = 
       DBG(addr, inst, rtn, rtnid, line, rtnname, assembly, filename+1);
  }
  fclose(fp);

  LOG(format("DebugInfo import: %d lines\n") % cnt);
}

VOID
DebugInfo::Export(const std::string& filename)
{
  FILE* fp = fopen(filename.c_str(), "w");

  for (btree::btree_map<II,DBG>::iterator it = _dbg.begin();
       it != _dbg.end();
       ++it)
  {
    DBG dbg = it->second;
    assert(dbg.instance == 0 || dbg.addr == MODEL_INST_ADDR);
    fprintf (fp, "%lx %lx %lx %lu %s %lu \"%s\" %s\n",
             dbg.addr, dbg.instance, dbg.rtn, dbg.rtnid, dbg.rtnname.c_str(), 
             dbg.line, dbg.assembly.c_str(), dbg.filename.c_str());
  }

  fclose(fp);
  LOG(format("DebugInfo export: %d lines\n") % _dbg.size());
}

#endif // DEBUG_INFO_H 
