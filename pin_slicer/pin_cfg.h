#ifndef PIN_CFG_H
#define PIN_CFG_H

#include "cfg.h"

#include "pin.H"
#include <set>

#include "pin_inst_descriptor.h"

class PIN_CFG : public CFG
{
private:
  vector<Node*> stack;

public:
  VOID EnterInstruction(INSDESC* ins);
  VOID EnterFunction();
  VOID LeaveFunction();
  Node& Find(INSDESC* ins);
};

#endif //PIN_CFG_H
