#ifndef PIN_ADDRESS_TRANSLATOR_H
#define PIN_ADDRESS_TRANSLATOR_H

#include <map>
#include <stdio.h>
#include <string>
#include <cstring>
#include "pin.H"
#include "output.h"

class PIN_Address_Translator
{
  struct IMG_Info {
    ADDRINT old_start;
    ADDRINT old_end;
    ADDRINT new_start;
    string name;
  };

  map<string, IMG_Info*> trans_by_name;
  // fix_name(img name)  -> IMG_Info
  map<ADDRINT, IMG_Info*> trans_by_addr;
  // end_addr -> IMG_Info

  inline IMG_Info const * find_by_address(ADDRINT addr) const {
    map<ADDRINT, IMG_Info*>::const_iterator it = trans_by_addr.lower_bound(addr);
    if(it != trans_by_addr.end() && addr >= it->second->old_start)
      return it->second;
    else 
      return NULL;
  }

  static inline string fix_name(const string& name) {
    int end = name.rfind(".so");
    if (end == -1) {
     end = name.length() - 1;
    }else end += 2;
    int start = name.find("/");
    if (start < 0) start++;
    return name.substr(start,end-start+1);
  }

public:
  inline bool Lookup(ADDRINT addr,  string& out_img_name, ADDRINT& out_offset) const {
    IMG_Info const * i = find_by_address(addr);
    if(i != NULL) {
      out_img_name = i->name;
      out_offset = addr - i->old_start;
      return true;
    }
    else
      return false;
  }

  inline bool Convert_Address(ADDRINT old_address, ADDRINT& new_address) const {
    IMG_Info const * i = find_by_address(old_address);
    if(i != NULL && i->new_start != 0) {
      new_address = i->new_start + (old_address - i->old_start);
      return true;
    }   
    return false;
  }

  inline void Mark_IMG_Address(const string& img_name, ADDRINT start_addr) {
    map<string, IMG_Info*>::iterator it = trans_by_name.find(fix_name(img_name));
    if(it != trans_by_name.end()) {
      it->second->new_start = start_addr;
    }
  }

  void Import(const string& file_path) {
    LOG(format("Translation File: %s\n") % file_path);
    FILE* trans_file = fopen(file_path.c_str(), "r");
    if(trans_file == NULL) {
      LOG("Error Opening AT File!\n");
      return;
    }
#define BUF_SZ (2046)
    char buffer[BUF_SZ];
    memset(buffer, 0, BUF_SZ);
    while (fgets(buffer, BUF_SZ, trans_file)) {
      IMG_Info* i;
      ADDRINT start, len;
      char img[BUF_SZ];
      memset(img, 0, BUF_SZ);
      sscanf(buffer, "%s\t%lx->%ld->%*x\n", img, &(start), &(len));
      if(strchr(img, '[') != NULL) continue;
      if(img[0] == '!') memmove(img, img+1, BUF_SZ-1);
      string img_name = img;
      map<string, IMG_Info*>::iterator it = trans_by_name.find(fix_name(img_name));
      if(it != trans_by_name.end()) {
        i = it->second;
        if(start < i->old_start) // new one is in front of old 
        {
          i->old_start = start;
        }
        else if(i->old_end < start + len) // new one is after old one.
        {
          trans_by_addr.erase(i->old_end);
          trans_by_addr[start+len] = i;
          i->old_end = start + len;
        }
        else
        {
          LOG(format(" AT inside? %lx - %lx %s\n") % start % (start + len) % i->name);
        }
      }
      else {
        i = new IMG_Info;
        i->old_start = start;
        i->old_end = start + len;
        i->new_start = 0;
        i->name = img_name;
        trans_by_name[fix_name(i->name)] = i;
        trans_by_addr[i->old_end] = i;
      }
      LOG(format("AT: %lx - %lx %s\n") % i->old_start % i->old_end % i->name);
    }
#undef BUF_SZ
  }
};

#endif //PIN_ADDRESS_TRANSLATOR_H
