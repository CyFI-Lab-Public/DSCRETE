#ifndef INST_DESCRIPTOR_H
#define INST_DESCRIPTOR_H

#include "pin.H"

#include <map>
#include "pin_helper.h"

struct INSDESC {

  ADDRINT addr = 0;
  ADDRINT instance = 0;

  INSDESC() {}
  INSDESC(ADDRINT a, ADDRINT i) : addr(a), instance(i) {};
  VOID initialize(INS ins);
  VOID initialize(ADDRINT address);

  static inline ADDRINT key(INS ins) { return INS_Address(ins); }
};

class Instructions
{
  map<ADDRINT, INSDESC> elems;

  static inline ADDRINT key(INS ins) { return INS_Address(ins); }

public:
  inline INSDESC& operator[](ADDRINT key) { return elems[key]; }
  inline INSDESC& operator[](INS ins) { return elems[key(ins)]; }
  inline INSDESC* find(ADDRINT key) { 
    map<ADDRINT, INSDESC>::iterator it = elems.find(key);
    if(it == elems.end())
      return NULL;
    else
      return &(it->second);
  }
  INSDESC* NewINS(INS ins);
  INSDESC* NewINS(ADDRINT addr);
};

#endif // INST_DESCRIPTOR_H
