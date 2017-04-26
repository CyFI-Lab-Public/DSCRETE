#ifndef ANALYSIS_DATATYPES_H
#define ANALYSIS_DATATYPES_H

#include <string>
#include <cstring>
#include "pin_types.h"

struct II {
  ADDRINT addr = 0;
  ADDRINT instance = 0;

  II() {}
  II(ADDRINT _addr, ADDRINT _instance)
    : addr(_addr), instance(_instance) {}
};

static inline bool operator< (const II& lhs, const II& rhs)
{ return lhs.addr < rhs.addr || (lhs.addr == rhs.addr && lhs.instance < rhs.instance); }
static inline bool operator==(const II& lhs, const II& rhs)
{ return lhs.addr == rhs.addr && lhs.instance == rhs.instance; }



enum DEP_TYPE {REG_DEP = 0, MEM_DEP = 1, CONTROL_DEP = 2};
struct DEP {
  II ii;
  DEP_TYPE type;
  ADDRINT value; // only valid for data deps
  union {
    ADDRINT addr;
    ADDRINT reg; // should be REG, but I know the size of this :)
  };
};

static inline bool operator< (const DEP& lhs, const DEP& rhs)
{ return lhs.ii < rhs.ii || 
         (lhs.ii == rhs.ii && lhs.type < rhs.type) ||
         (lhs.ii == rhs.ii && lhs.type == rhs.type && lhs.type != CONTROL_DEP &&
            lhs.addr < rhs.addr); }

//static inline bool operator== (const DEP& lhs, const DEP& rhs)
//{ return lhs.ii == rhs.ii && lhs.dep == rhs.dep; }

static inline DEP StringtoDEP(const std::string& s) {
  DEP ret; // this is ok in C++ because of temporary life extension... wow.
  char type[20];
  char *str = (char *)s.c_str();
  sscanf(str, "%lx %ld %s", &ret.ii.addr, &ret.ii.instance, type);
  if(strncmp(type, "CONTROL_DEP", 11) == 0)
    ret.type = CONTROL_DEP;
  else {
    str = strstr(str, type) + strlen(type);
    if (strncmp(type, "MEM_DEP", 7) == 0) {
      ret.type = MEM_DEP;
      sscanf(str,"%lx %lx", &ret.addr, &ret.value);
    } else { //type == REG_DEP
      ret.type = REG_DEP;
      sscanf(str,"%ld %*s %lx", &ret.reg, &ret.value);
    }
  }
  return ret;
}

#ifdef FORENSIX_SLICING
#include "pin_helper.h"
static inline std::string DEPtoString(const DEP& d) {
  std::string ret = hexstr(d.ii.addr) + " " + decstr(d.ii.instance) + " ";
  if(d.type == CONTROL_DEP)
    ret += "CONTROL_DEP";
  else {
    if (d.type == MEM_DEP)
      ret += "MEM_DEP " + hexstr(d.addr);
    else // d.dep_type == REG_DEP
      ret += "REG_DEP " + decstr(d.reg) + " (" + REG_StringShort((REG)d.reg) + ")";
    ret += " "+hexstr(d.value)+" ["+ToPrintableString(&d.value, sizeof(ADDRINT))+"]";
  }
  return ret;
}
#endif 


#endif // ANALYSIS_DATATYPES_H
