#ifndef RTN_DESCRIPTOR_H
#define RTN_DESCRIPTOR_H

#include "pin.H"

//#include "btree/btree_map.h"
#include <map>
#include "pin_helper.h"

struct RTNDESC {
  ADDRINT addr = 0;
  string name;

  RTNDESC() {}
};

class Routines
{
  map<ADDRINT, RTNDESC> elems;

public:
  RTNDESC& operator[](ADDRINT key);
  inline RTNDESC* find(ADDRINT key) 
  {
    map<ADDRINT, RTNDESC>::iterator it = elems.find(key);
    if(it != elems.end())
      return &(it->second);
    else
      return NULL; 
  }
};
#endif // RTN_DESCRIPTOR_H
