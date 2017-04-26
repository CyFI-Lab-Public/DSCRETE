#include <string>
#include "string.h"
#include "pin.H"
#include "pin_forensix_slicing.h"
#include "pin_inst_descriptor.h"
#include "pin_models.h"
#include "pin_helper.h"
#include "printf.h"
#undef NDEBUG
#include <cassert>

Called_Model::Called_Model()
{
  info = NULL;
  caller = INSDESC();
  current_caller_sp = 0;
  orig_num_args = 0;
}

Called_Model::Called_Model(Model_Info* my_model, 
                           INSDESC& c,
                           ADDRINT c_sp,
                           const CONTEXT *ctxt)
{
  info = my_model;
  caller = c;
  current_caller_sp = c_sp;
  orig_num_args = info->args.num_args();
  if(info->has_ellips)
    Handle_Ellipsis(ctxt);
  info->args.set_stack_args_relative_to(current_caller_sp);
}

void Called_Model::Return()
{
  while(info->args.num_args() > orig_num_args)
  {
    info->args.remove_last();
  }
  info = NULL;
}

inline int
Called_Model::get_arg_number_by_name(const string& name)
{
  for(int i = 0; i < info->args.num_args(); i++)
  {
    if(info->args.get(i).name == name) return i;
  }
  return -1;
}

inline bool
Called_Model::is_printf_style()
{
  const char * name = info->name.c_str();
  unsigned len = info->name.length();
  if (name[len-1] == 'f')
    return true;
  if (strncmp(name + len - 5, "f_chk", 5) == 0)
    return true;
  return false;
}

inline void 
Called_Model::handle_printf_format(const char* fmt)
{
  int n_args = parse_printf_format(fmt,0,NULL);
  int args[n_args];
  parse_printf_format(fmt, n_args, args);
  for(int i = 0; i < n_args; i++)
  {
    string name = (format("fmt%d") % i).str();
    switch (args[i] & ~PA_FLAG_MASK) {
      case PA_FLOAT:
      case PA_DOUBLE:
        info->args.new_arg(Model_Info::Model_Arg::TYPE_FLOAT, name);
        break;
      default:
        info->args.new_arg(Model_Info::Model_Arg::TYPE_INT, name);
        break;
    }
  }
}

inline void
Called_Model::Handle_Ellipsis(const CONTEXT* ctxt)
{
  if(info->img_name == "libc.so" && is_printf_style())
  {
    int param_num = get_arg_number_by_name("__format");
    assert(param_num < 6);
    if(param_num < 0) param_num = get_arg_number_by_name("__fmt");
    assert(param_num < 6);
    if(param_num < 0) goto errout;
    handle_printf_format((const char *)PIN_GetContextReg(ctxt, REG_INT_PARAM(param_num)));
    return;
  }

errout:
  LOG(format("WARNING: Call to %s@%s has ellipsis param!\n"
             "  Can not determine additional args!\n")
        % info->name % info->img_name);
}
