#include "pin.H"

#include "pin_cfg.h"
#include "pin_inst_descriptor.h"
#include "pin_forensix_slicing.h"
#include "output.h"

VOID PIN_CFG::EnterInstruction(INSDESC* ins)
{
  assert (ins->addr != 0);

  Node* curr_Node = &nodes[ins->addr];
  curr_Node->addr = ins->addr;
  if (ins != INS_exit && curr_Node->ipdom == 0 && valid) {
    valid = FALSE;
    LOG("CFG IS NOT VALID\n");
  }

  if (prev_Node && prev_Node != curr_Node) {
//      LOG("CFG -- " + hexstr(prev_Node->addr) + " -> " + hexstr(curr_Node->addr) + "\n");
    if (prev_Node->succ.find(curr_Node) == prev_Node->succ.end()) {
      prev_Node->succ.insert(curr_Node);
      prev_Node->ipdom = 0;
      valid = FALSE;
    }
  }
  prev_Node = curr_Node;
}

VOID PIN_CFG::EnterFunction()
{
  stack.push_back(prev_Node);
  prev_Node = 0;
}

VOID PIN_CFG::LeaveFunction()
{
  prev_Node = stack.back();
  stack.pop_back();
}

CFG::Node& PIN_CFG::Find(INSDESC* ins)
{
  return CFG::Find(ins->addr);
}
