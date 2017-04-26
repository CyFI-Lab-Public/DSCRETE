#include "pin.H"

#include "pin_inst_descriptor.h"

#undef NDEBUG
#include <cassert>

VOID INSDESC::initialize(INS ins)
{
  addr = INS_Address(ins);
  instance = 0;
}

VOID INSDESC::initialize(ADDRINT address)
{
  addr = address;
  instance = 0;
}

INSDESC* Instructions::NewINS(INS ins)
{
  INSDESC& iidesc = elems[key(ins)];
  iidesc.initialize(ins);
  return find(INS_Address(ins));
}

INSDESC* Instructions::NewINS(ADDRINT addr)
{
  ADDRINT a = addr;
  assert(a && "Zero Address Added?");
  INSDESC& iidesc = elems[addr];
  iidesc.initialize(addr);
  return find(addr);
}
