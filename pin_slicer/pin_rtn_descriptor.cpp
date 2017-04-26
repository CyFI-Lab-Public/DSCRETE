#include "pin.H"

#include "pin_rtn_descriptor.h"

RTNDESC& Routines::operator[](ADDRINT addr)
{
  map<ADDRINT, RTNDESC>::iterator it = elems.find(addr);
  if (it != elems.end()) {
    return it->second;
  }
  else {
    RTNDESC& rtndesc = elems[addr];
    rtndesc.addr = addr;
    rtndesc.name = hexstr(addr);
    return rtndesc;
  }
}

