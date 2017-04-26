#ifndef PIN_CRIT_FUNCS_H
#define PIN_CRIT_FUNCS_H

#define GDK_PIXBUF_OUTPUT
//#undef GDK_PIXBUF_OUTPUT

#include <map>
#include <stdio.h>
#include <string.h>
#include "pin.H"
#include "output.h"

class PIN_Critical_Funcs_Handler
{
  class Crit_Arg {
  public:
    uint8_t first_arg;
    enum len_type { STR
                    , OTHER_ARG
                    , PRINT_F
                    , VA_LIST
#ifdef GDK_PIXBUF_OUTPUT
                    , GDK_PIXBUF
#endif
                  } len_type;
    uint8_t other_arg;
  
    void init_from_string(char *c)
    {
      first_arg = c[0] - '0';
      switch(c[1]) {
#ifdef GDK_PIXBUF_OUTPUT
        case 'p':
          len_type = GDK_PIXBUF;
          break;
#endif
        case 's':
          len_type = STR;
          break;
        case 'a':
          len_type = OTHER_ARG;
          other_arg= c[2] - '0';
          break;
        case 'f':
          len_type = PRINT_F;
          break;
        case 'v':
          len_type = VA_LIST;
          other_arg= c[3] - '0';
          break;
        default:
          break;
      }
    }
  };

public:
  class Crit_Func{
public:
    ADDRINT offset;
    string img_name;
    Crit_Arg arg;
    bool replaced;
  };

private:
  map<pair<ADDRINT, string>, Crit_Func> funcs;
  ADDRINT not_yet_replaced = 0;
#ifdef GDK_PIXBUF_OUTPUT
  const char png_str[4] = "png";
  AFUNPTR ptr_gdk_pixbuf_save_to_bufferv;
#endif

public:
#ifdef GDK_PIXBUF_OUTPUT
  inline VOID Init_GDK_Pixbuf_Output(AFUNPTR bufferv_func_ptr) {
    ptr_gdk_pixbuf_save_to_bufferv = bufferv_func_ptr;
  }
#endif

  inline Crit_Func* Lookup(ADDRINT offset, const string& img_name)
  {
    map<pair<ADDRINT, string>, Crit_Func>::iterator it = 
                            funcs.find(make_pair(offset, img_name));
    if(it == funcs.end()) {
      return NULL;
    } else {
      return &(it->second);
    }
  }

  inline bool All_Replaced() const 
  {
    return not_yet_replaced == 0;
  }

  inline void Mark_Replaced(Crit_Func* f)
  {
    if(!f->replaced) {
      f->replaced = true;
      not_yet_replaced--;
    }
  }

  inline void Handle(Crit_Func* f, const CONTEXT* ctxt, void*& ptr, ADDRINT& len)
  {
    switch(f->arg.len_type)
    {
#ifdef GDK_PIXBUF_OUTPUT
      case Crit_Arg::GDK_PIXBUF:
      {
        char* pixbuf = (char *)PIN_GetContextReg(ctxt, REG_INT_PARAM(f->arg.first_arg));
        ADDRINT ret;
        is_slave = false;
        PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT,
                                    ptr_gdk_pixbuf_save_to_bufferv,
                                    PIN_PARG(ADDRINT), &ret,
                                    PIN_PARG(char*), pixbuf,
                                    PIN_PARG(char**), &ptr,
                                    PIN_PARG(ADDRINT*), &len,
                                    PIN_PARG(char*), png_str,
                                    PIN_PARG(char*), NULL,
                                    PIN_PARG(char*), NULL,
                                    PIN_PARG(char*), NULL,
                                    PIN_PARG_END() );
        is_slave = true;
        return;
      }
#endif
      case Crit_Arg::STR:
      {
        char *p = (char *)PIN_GetContextReg(ctxt, REG_INT_PARAM(f->arg.first_arg));
        len = ::strlen((char*)p);
        ptr = (void *)new char [len];
        strcpy((char *)ptr, p);
        return;
      }
      case Crit_Arg::OTHER_ARG:
      {
        void *p = (void *)PIN_GetContextReg(ctxt, REG_INT_PARAM(f->arg.first_arg));
        len = PIN_GetContextReg(ctxt,REG_INT_PARAM(f->arg.other_arg));
        ptr = (void *)new char [len];
        memcpy(ptr, p, len);
        return;
      }
      case Crit_Arg::PRINT_F:
      { 
        uint8_t fmt_arg_num = f->arg.first_arg;
        uint8_t* reg_area = new uint8_t[(MAX_INT_REG_PARAMS * sizeof(ADDRINT)) +
                             ((MAX_FLOAT_REG_PARAMS * 2) * (sizeof(ADDRINT) * 2))];
        unsigned int gp_offset = 0;
        for(uint8_t arg_num = fmt_arg_num + 1; arg_num < MAX_INT_REG_PARAMS; arg_num++)
        {
          uint8_t byte_offset = arg_num * sizeof(ADDRINT);
          if(gp_offset == 0) gp_offset = byte_offset;
          ADDRINT* dest = ((ADDRINT*)(&(reg_area[byte_offset])));
          ADDRINT val = PIN_GetContextReg(ctxt, REG_INT_PARAM(arg_num));
          *dest = val;
        }
        unsigned int fp_offset = (MAX_INT_REG_PARAMS * sizeof(ADDRINT));
        for(uint8_t arg_num = 0; arg_num < MAX_FLOAT_REG_PARAMS; arg_num++)
        {
          PIN_REGISTER r;
          PIN_GetContextRegval(ctxt, REG_FLOAT_PARAM(arg_num), (UINT8*)&r);
          uint8_t byte_offset = fp_offset + (arg_num * (sizeof(ADDRINT)*2));
          memcpy(&(reg_area[byte_offset]), &r, sizeof(PIN_REGISTER));
        }
        ADDRINT* sp = (ADDRINT*)PIN_GetContextReg(ctxt, REG_STACK_PTR);
        va_list va = {{gp_offset, fp_offset, sp, reg_area}};
        va_list vacpy = {{gp_offset, fp_offset, sp, reg_area}};
        const char* fmt_str = (const char*)PIN_GetContextReg(ctxt, REG_INT_PARAM(fmt_arg_num));
        len = vsnprintf(NULL, 0, fmt_str, va);
        ptr = (void *)new char [len];
        len = vsnprintf((char*)ptr, len, fmt_str, vacpy);
        delete[] reg_area;
        return;
      }
      case Crit_Arg::VA_LIST:
      {
        char * fmt = (char *)PIN_GetContextReg(ctxt, REG_INT_PARAM(f->arg.first_arg));
        void * va_ptr = (void *)PIN_GetContextReg(ctxt, REG_INT_PARAM(f->arg.other_arg));
        va_list* va = reinterpret_cast<va_list*>(&va_ptr);
        va_list copy_va;
        va_copy(copy_va, *va);
        len = vsnprintf(NULL,0, fmt, copy_va);
        va_end(copy_va);
        ptr = (void *)new char [len+1];
        va_copy(copy_va, *va);
        vsnprintf((char*)ptr, len, fmt, copy_va);
        va_end(copy_va);
        return;
      }
      default:
        return;
    }
  }

  void Import(const string& file_path)
  {
    FILE* fp = fopen(file_path.c_str(), "r");
    if(fp == NULL) {
      LOG(format("Error Opening Crit Funcs File: %s\n") % file_path);
      return;
    }
#define BUF_SZ (1024)
    char buffer[BUF_SZ];
    memset(buffer, 0, BUF_SZ);
    while (fgets(buffer, BUF_SZ, fp))
    {
      Crit_Func f;
      f.replaced = false;
      // got address and img line
      char name[BUF_SZ];
      memset(name, 0, BUF_SZ);   
      sscanf(buffer, "%lx %s", &(f.offset), name);
      f.img_name = name;
      // get arg line
      memset(buffer, 0, BUF_SZ);
      fgets(buffer, BUF_SZ, fp);
      f.arg.init_from_string(buffer);
      LOG(format("Read Crit: %lx %s %s\n") % f.offset % f.img_name % buffer);
      funcs[make_pair(f.offset, f.img_name)] = f;
      not_yet_replaced++;

      // get def line (we dont use that)
      fgets(buffer, BUF_SZ, fp);
      memset(buffer, 0, BUF_SZ);
    }
#undef BUF_SZ
    fclose(fp);
  }
};

#endif //PIN_CRIT_FUNCS_H
