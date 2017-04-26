#ifndef PIN_FORENSIX_SCANNER_H
#define PIN_FORENSIX_SCANNER_H

#include "analysis_datatypes.h"
#include <map>
#include <string>
#include <utility>
#include "pin_address_translator.h"

class ClosurePoint {
public:
  string img_name;
  ADDRINT offset;
  DEP d;
  BOOL done;

  ClosurePoint() {};

  ClosurePoint(DEP dc, const PIN_Address_Translator& trans) {
     d = dc;
     done = false;
     trans.Lookup(dc.ii.addr, img_name, offset);
  }
  ClosurePoint(const string& s) {
    string s_end = s.substr(s.rfind("]")+2, string::npos);
    char name[1024];
    memset(name, 0, 1024);
    sscanf(s_end.c_str(), "%lx %s\n", &(offset), name);
    img_name = name;
    d = StringtoDEP(s);
    done = false;
  }
  inline string ToString() {
    return DEPtoString(d) + " " + hexstr(offset) + " " + img_name;
  }
};


#define AGGRESSIVE_LOGGING 0

extern bool is_slave; // controls if you think you are a slave... I know I am :(

#endif // PIN_FORENSIX_SCANNER_H
