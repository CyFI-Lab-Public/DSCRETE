#ifndef SLICING_MODEL_H
#define SLICING_MODEL_H

#include <string>
#include "pin.H"
#include "pin_inst_descriptor.h"

VOID Enter_Model(RTN rtn, const string& rtnname, 
                 IMG img, const string& imgname,
                 const CONTEXT* ctxt, INSDESC* caller);

VOID Leave_Model(const CONTEXT* ctxt);

VOID Perform_Cached_Model_RegOps();
VOID Clear_Cached_Model_RegOps();
BOOL Has_Cached_Model_RegOps();

VOID ShutdownModels();

#endif // SLICING_MODEL_H
