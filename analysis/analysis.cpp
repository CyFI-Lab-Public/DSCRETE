/**
 * After pin_slicer has collected the dynamic program trace, this
 *  program computes the backward slice of the selected bcrit values. 
 */

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <fstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "readwrite.h"
#include "analysis_datatypes.h"
#include "forensix_slicing_constants.h"
#include "output.h"
#include "trace.h"
#include "debug_info.h"
#include "cfg.h"

using namespace std;

DebugInfo DEBUG_INFO;
string command_directory;
/*
bool VerifyTrace(SLICETRACE& trace)
{
  for (UINT64 i = 0; i < (trace.size - 1); i++) {
    DEPENDENCY& dep1 = trace.get_dep(i);
    DEPENDENCY& dep2 = trace.get_dep(i+1);
    if((char*)(&(dep1.dependencies[dep1.ndep])) != (char*)(&(dep2.ndep))) {
      TRACEENTRY& e1 = trace.entries[i];
      TRACEENTRY& e2 = trace.entries[i+1];
      const DBG&  n1 = DEBUG_INFO.get(e1.addr, (e1.addr == MODEL_INST_ADDR ? e1.inst : 0));
      const DBG&  n2 = DEBUG_INFO.get(e2.addr, (e2.addr == MODEL_INST_ADDR ? e2.inst : 0));
      LOG("DEP SIZE VIOLATIONS!\n");
      LOG(format("E1: 0x%lx %lu [%lu,%lu]: %s (%s) (%s:%lu)\n") % 
           e1.addr % e1.inst % e1.pid % e1.tid %n1.assembly.c_str() %
           n1.rtnname.c_str() % n1.filename.c_str() %
           n1.line);
      LOG(format("E2: 0x%lx %lu [%lu,%lu]: %s (%s) (%s:%lu)\n") % 
           e2.addr % e2.inst % e2.pid % e2.tid % n2.assembly.c_str() %
           n2.rtnname.c_str() % n2.filename.c_str() %
           n2.line);
//      return false;
    }
  }
 
  set<II> missing;
  for (UINT64 i = trace.size - 1; ; i--) {
    TRACEENTRY& e = trace.entries[i];
    missing.erase(e);
    DEPENDENCY& dep = trace.get_dep(i);
    for(DEP* d = &dep.dependencies[0]; d < &dep.dependencies[dep.ndep]; d++)
      missing.insert(d->ii);
  }
  if(!missing.empty()) {
    LOG("DEP MISSING!\n");
    return false;
  }
}
*/

vector<UINT64>*
Slice(const string& basename, SLICETRACE& trace1, vector<II>* criteria)
{
  LOG("SLICE\n");
  string filename = basename + "slice";

  vector<UINT64>* slice = new vector<UINT64>;
  set<II> deps(criteria->begin(), criteria->end());
  UINT64 progress = 0;

  for (UINT64 i = trace1.size - 1; ; i--) {
    // Step through each instruction entry in the trace
    TRACEENTRY& e = trace1.entries[i];
    DEPENDENCY& dep = trace1.get_dep(i);

    // if dep contains e
    set<II>::iterator it = deps.find(e);
    if (it != deps.end()) {
      deps.erase (it);

      // the slice should contain e (instruction entry i)
      slice->push_back(i);

      // and we are now dependant on all of it's dependencies
      for(DEP* d = &dep.dependencies[0]; d < &dep.dependencies[dep.ndep]; d++)
        deps.insert (d->ii);
    }

    if (++progress >= 1000000) {
      LOG(format("%lu / %lu (%f%%)\n")
           % (trace1.size - i)
           % trace1.size
           % ((trace1.size - i) / (double)trace1.size * 100));
      progress = 0;
    }

    if (i == 0) { break; }
  }

  FILE* fp = fopen(filename.c_str(), "w");
  for (UINT64 i : *slice)
    fprintf (fp, "%lu\n", i);
  fclose(fp);
  LOG(format("%lu items stored in slice\n") % slice->size());
  return slice;
}

bool member_in(set<II>& deps, DEPENDENCY& dep)
{
  for(DEP* d = &dep.dependencies[0]; d < &dep.dependencies[dep.ndep]; d++)
    if (deps.find(d->ii) != deps.end()) return true;
  return false;
}

vector<UINT64>*
Chop(const string& basename, SLICETRACE& trace1,
       vector<UINT64>* slice,
       vector<II>* criteria)
{
  LOG("CHOP\n");
  string filename = basename + "chop";


  if (criteria == NULL) return slice;

  set<II> deps(criteria->begin(), criteria->end());
  set<II> crit = deps;
  set<UINT64> chop;
  UINT64 progress = 0;

  for (UINT64 i = 0; i < trace1.size; i++) {
    TRACEENTRY& e = trace1.entries[i];
    DEPENDENCY& dep = trace1.get_dep(i);

    if ((crit.find(e) != crit.end()) || member_in(deps, dep)) {
      chop.insert (i);
      deps.insert (e);
    }

    if (++progress >= 1000000) {
      LOG(format("%lu / %lu (%f%%)\n") 
           % (i+1)
           % trace1.size
           % ((i+1) / (double)trace1.size * 100));
      progress = 0;
    }
  }

  vector<UINT64>* chopping = new vector<UINT64>;

  for (UINT64 i : (*slice)) {
    if (chop.find(i) != chop.end())
      chopping->push_back (i);
  }

  FILE* fp = fopen(filename.c_str(), "w");
  for (UINT64 i : *chopping)
    fprintf (fp, "%lu\n", i);
  fclose(fp);
  LOG(format("%lu items stored\n") % chopping->size());

  return chopping;
}

void dump_slice(const string& basename, SLICETRACE& trace1, vector<UINT64>* slice)
{
  FILE* fp = fopen((basename + "dump_slice").c_str(), "w"); 
  for (UINT64 i : *slice) {
    TRACEENTRY& e = trace1.entries[i];
    DEPENDENCY& d = trace1.get_dep(i);
    const DBG&  n = DEBUG_INFO.get(e.addr, (e.addr == MODEL_INST_ADDR ? e.inst : 0));

    fprintf (fp, "%lu==============================\n", d.ndep);
    fprintf (fp, "0x%lx %lu : %s (%s) (%s:%lu)\n", 
                 e.addr, e.inst, n.assembly.c_str(),
                 n.rtnname.c_str(), n.filename.c_str(),
                 n.line);
    for(DEP* de = &d.dependencies[0]; de < &d.dependencies[d.ndep]; de++) {
      fprintf (fp, "    0x%lx %lu ", de->ii.addr, de->ii.instance);
      if(de->type == REG_DEP)
        fprintf (fp, "RD - reg %ld <%lx>\n", de->reg, de->value); 
      else if(de->type == MEM_DEP)
        fprintf (fp, "MD - addr %lx <%lx>\n", de->addr, de->value); 
      else // CONTROL DEP
        fprintf (fp, "CD\n"); 
    }
  }
  fclose(fp);
}

/*
void
function_data_dependency(SLICETRACE& trace1, vector<pair<UINT64, UINT32>>* slice)
{
  FILE* fp = fopen((trace1.directory + "/" + trace1.directory + ".fundep").c_str(), "w");
  set<II> deps;
  set< pair<UINT64, UINT64> > fundeps;

  for (auto i : *slice) {
    deps.insert (trace1.entries[i.first]);
  }

  for (UINT64 i = trace1.size - 1; ; i--) {
    TRACEENTRY& e = trace1.entries[i];
    DEPENDENCY& dep = trace1.get_dep(i);

    if (deps.find(e) != deps.end()) {
      for (UINT64 j = 0; j < dep.ndep; j++) {
        if (deps.find(dep.dependencies[j].ii) != deps.end()) {
          const DBG& n2 = DEBUG_INFO[dep.dependencies[j].ii.addr];
          const DBG& n1 = DEBUG_INFO[e.addr];

          if (n1.rtn == n2.rtn) { continue; }

          pair<UINT64, UINT64> xx(n1.rtn, n2.rtn);
          if (fundeps.find(xx) == fundeps.end()) {

            fprintf (fp, "%lx %lx\n", xx.first, xx.second);

            fundeps.insert (xx);
          }
        }
      }
    }

    if (i == 0) { break; }
  }

  fclose(fp);
}
*/

static inline std::string &ltrim(std::string &s)
{
  s.erase(s.begin(),
          std::find_if(s.begin(), 
                       s.end(), 
                       std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

string
getsourceline(string filename, int lineno)
{
  //    filename.replace (filename.find (PREFIX), strlen(PREFIX), "");
  if (lineno == 0) {
    return "";
  }

  ifstream file(filename.c_str());
  string line;
  int n = 1;

  while (getline(file, line)) {
    if (n == lineno) {
      ltrim(line);
      return line;
    }
    n++;
  }

  return "";
}

/**
void dump_slice_function(const string& basename, SLICETRACE& trace1, vector<pair<UINT64, UINT32>>* slice)
{
  FILE* fp = fopen((basename + "xxx").c_str(), "w");

  set<II> deps;
  for (auto i : *slice) {
    deps.insert (trace1.entries[i.first]);
  }

  map<UINT64, map<UINT64, set<UINT64>>> spf;
  map<UINT64, string> rtnnames;
  map<UINT64, UINT32> flags;

  for (auto i : *slice) {
    TRACEENTRY& e = trace1.entries[i.first];
    DEPENDENCY& dep = trace1.get_dep(i.first);
    const DBG& n = DEBUG_INFO.get(e.addr, (e.addr == MODEL_INST_ADDR ? e.inst : 0));

    rtnnames[n.rtn] = n.rtnname;
    map<UINT64, set<UINT64>>& sss = spf[n.rtn];
    set<UINT64>& ss = sss[e.addr];

    flags[e.addr] |= i.second;

    for (UINT64 j = 0; j < dep.ndep; j++) {
      if (deps.find(dep.dependencies[j].ii) != deps.end()) {
        ss.insert (dep.dependencies[j].ii.addr);
      }
    }
  }

  for (auto i : spf) {
    fprintf (fp, "RTN: %s\n", rtnnames[i.first].c_str());
    for (auto j : i.second) {
      const DBG& n1 = DEBUG_INFO.get(j.first, 0);
      string source1 = getsourceline(n1.filename, n1.line);

      fprintf (fp, "%p(%d): %s\n%s\n", (void*)j.first, flags[j.first], n1.assembly.c_str(), source1.c_str());

      for (UINT64 k : j.second) {
        const DBG& n2 = DEBUG_INFO.get(k,0);
        string source2 = getsourceline(n2.filename, n2.line);

        fprintf (fp, "\t%p: %s\n\t\t%s, %s\n", (void*)k, n2.assembly.c_str(), n2.rtnname.c_str(), source2.c_str());
      }
    }
    fprintf (fp, "\n\n");
  }


  fclose(fp);
}
**/

vector<II>* load_dependencies(const string& path)
{
  FILE* fp = fopen(path.c_str(), "rt");
  if (!fp) return NULL;

  vector<II>* ret = new vector<II>;
  LOG(format("Loading dependencies from %s\n") % path.c_str());

  II temp;
  char buffer[1024];
  while (fgets(buffer, 1024, fp) != NULL) {
    int check = sscanf(buffer, "%p %lu", (void**)&temp.addr, &temp.instance);
    assert(check == 2);
    ret->push_back(temp);
  }

  LOG(format("  %lu dependencies loaded\n") % ret->size());
  fclose(fp);
  return ret;
}

int main(int argc, char** argv)
{
  if (argc != 2) {
    LOG(format("Usage: %s [output directory]\n") % argv[0]);
    return 1;
  }

  string argv0 = argv[0];
  size_t p0 = argv0.rfind("/");
  if (p0 != string::npos) {
    command_directory = argv0.substr(0, p0 + 1);
  }

  DEBUG_INFO.Import(DEBUG_FILE_NAME);
  vector<II>* bcrit = load_dependencies("bcrit");
  vector<II>* fcrit = load_dependencies("fcrit");

  assert (bcrit != NULL);

  string directory = argv[1];

  SLICETRACE trace;
  trace.Import(directory);

  string basename = trace.directory + "/" + trace.directory + ".";

/*  if(!VerifyTrace(trace))
  {
    LOG("TRACE BAD!\n");
    return 2;
  }
*/
  vector<UINT64>* slice = Slice(basename, trace, bcrit);
  slice = Chop(basename, trace, slice, fcrit);

  LOG("DUMP SLICE\n");
  dump_slice(basename, trace, slice);

//  LOG("dump_slice_function\n");
//  dump_slice_function(basename, trace, slice);

  //LOG("function_data_dependency\n");
  //function_data_dependency(trace, slice);

  LOG("DONE\n");
}
