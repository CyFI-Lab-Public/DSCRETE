#ifndef PIN_MODELS_H
#define PIN_MODELS_H

#include "pin.H"
#include "pin_inst_descriptor.h"
#include <vector>

class Model_Info;

class Called_Model {
public:
  Model_Info* info;
  INSDESC caller;
  ADDRINT current_caller_sp;
  uint8_t orig_num_args;
  
  Called_Model();
  Called_Model(Model_Info* my_model, INSDESC& c, ADDRINT c_sp, const CONTEXT *ctxt);
  bool Is_Called() { return info != NULL; }
  void Return();

private:
  inline void Handle_Ellipsis(const CONTEXT* ctxt);
  inline void handle_printf_format(const char* fmt);
  inline bool is_printf_style();
  inline int get_arg_number_by_name(const string& name);
};

class Model_Info {
public:
  struct Model_Arg {
    typedef enum { TYPE_NONE, TYPE_INT, TYPE_FLOAT } TYPE;
    typedef enum { ARG_STACK, ARG_REG } LOC;
    TYPE type;
    string name;
    LOC loc;
    union {
      REG reg;
      ADDRINT stack_addr; // only valid for runtime args.
    };
    Model_Arg() { 
      type = TYPE_NONE;
      name = "";
      loc = ARG_STACK;
      stack_addr = 0;
    }
    bool operator == (const Model_Arg& other) const 
    { return type == other.type && loc == other.loc; }
  };

  class Model_Args {
    uint8_t n_int_reg;
    uint8_t n_float_reg;
    uint8_t n_stack;
    vector<Model_Arg> args;
  public:
    Model_Args() {
      n_int_reg = 0;
      n_float_reg = 0;
      n_stack = 0;
    }
    Model_Args(uint8_t init_cap) {
      n_int_reg = 0;
      n_float_reg = 0;
      n_stack = 0;
      args.reserve(init_cap);
    }
    inline uint8_t num_args() const { return args.size(); }
    inline uint8_t num_int_regs() const { return n_int_reg; }
    inline uint8_t num_float_regs() const { return n_float_reg; }
    inline uint8_t num_stack() const { return n_stack; }

    inline const Model_Arg& get(uint8_t arg_index) const { return args[arg_index]; }

    inline void remove_last() {
      Model_Arg a = args.back();
      if(a.loc == Model_Arg::ARG_STACK)
        n_stack--;
      else if(a.type == Model_Arg::TYPE_FLOAT)
        n_float_reg--;
      else
        n_int_reg--;
      args.pop_back();
    }

    inline void new_arg(Model_Arg::TYPE t, const string& name) {
      Model_Arg a;
      a.type = t;
      a.name = name;
      if (t == Model_Arg::TYPE_INT && n_int_reg < MAX_INT_REG_PARAMS) {
        a.loc = Model_Arg::ARG_REG;
        a.reg = REG_INT_PARAM(n_int_reg);
        n_int_reg++;
      }
      else if (t ==  Model_Arg::TYPE_FLOAT && n_float_reg < MAX_FLOAT_REG_PARAMS) {
        a.loc = Model_Arg::ARG_REG;
        a.reg = REG_FLOAT_PARAM(n_float_reg);
        n_float_reg++;
      }
      else {
        a.loc = Model_Arg::ARG_STACK;
        n_stack++;
      }
      args.push_back(a);
    }

    inline void set_stack_args_relative_to(ADDRINT sp) {
      uint8_t i = 0;
      for(vector<Model_Arg>::iterator it = args.begin();
          it != args.end(); it++)
      {
        if(it->loc == Model_Arg::ARG_STACK) {
          it->stack_addr = AFTER_CALL_STACK_PARAM(i, sp);
          i++;
        }
      }
    }

    bool operator == (const Model_Args& other) const { return args == other.args; }
  };

  string name;
  string img_name;
  Model_Arg::TYPE ret_type;
  Model_Args args;
  bool has_ellips;
  bool found; // no read from text so bool is ok.
  string found_name; // only valid if found! name in def!
 
  Model_Info() {
    name = "No Name";
    img_name = "No Img";
    ret_type = Model_Arg::TYPE_NONE;
    has_ellips = false;
    found = false;
    found_name = "Not Found";
  }
  
  Model_Info(const string& n, const string& i) {
    name = n;
    img_name = i;
    ret_type = Model_Arg::TYPE_NONE;
    has_ellips = false;
    found = false;
    found_name = "Not Found";
  }

  Called_Model Call(const CONTEXT *ctxt, INSDESC& caller, ADDRINT caller_sp) {
    return Called_Model(this, caller, caller_sp, ctxt);
  }

  bool operator == (const Model_Info& other) const
  {
    return name == other.name && 
           img_name == other.img_name &&
           has_ellips == other.has_ellips &&
           ret_type == other.ret_type &&
           args == other.args;
  }
};

#endif // PIN_MODELS_H
