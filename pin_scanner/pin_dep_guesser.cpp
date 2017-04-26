#include "pin.H"

#include <cstring>
#include <map>
#include <set>
#include <stack>
#include <fstream>
#include <string>
#include <vector>

#include "readwrite.h"
#include "pin_scan.h"
#include "analysis_datatypes.h"
#include "forensix_slicing_constants.h"
#include "pin_forensix_scanner.h"
#include "output.h"
#include "trace.h"
#include "debug_info.h"

using namespace std;

DebugInfo DEBUG_INFO;
PIN_Scan* scanner;

/* Configs */
#define SAVE_GUESSES
#define INST_GUESS (1)
//#define PRINT_GRAPHS
//#define ONE_PATH_CHECK

double SLICE_INCLUDE_RATIO; // ratio of slice to consider... 

class DepGraph {
public:
  class EDGE {
  public:
    II source;
    II dest;
    DEP_TYPE type;
    EDGE(II s, II d, DEP_TYPE t)
      : source(s), dest(d), type(t) {} 
    EDGE() {};

    bool operator< (const EDGE& rhs) const
    { return source < rhs.source || 
             (source == rhs.source && dest < rhs.dest) ||
             (source == rhs.source && dest == rhs.dest && type < rhs.type); }  
  };
private: 
  set<II> nodes;
  map<II, set<pair<II, DEP>>> missing_deps; // missing node -> nodes which dep on it
  map<II, set<DEP>> missing_deps_for_node;   // node -> deps it is missing.
  map<DEP_TYPE, set<DEP>> missing_deps_by_type; // dep type -> deps missing for that type
  set<EDGE> edges;
  map<II, set<II>> to_neighbors; // node -> nodes it points to.
  map<II, set<II>> from_neighbors; // node -> nodes point to it.
  //  A -> B implies: to_neighbors[A] = {B, ... } and from_neighbors[B] = {A, ...}

  inline void add_dep(II ii, DEP dep)
  { 
/**    LOG(format("ADDING %lx %d -> %lx %d\n")
          % ii.addr % ii.instance
          % dep.ii.addr % dep.ii.instance); */
    if( ii == dep.ii )
        return; // no self deps...
    if(nodes.find(dep.ii) != nodes.end())
        return;
    //assert(nodes.find(dep.ii) == nodes.end());
    missing_deps[dep.ii].insert(make_pair(ii,dep));
    missing_deps_for_node[ii].insert(dep);
    missing_deps_by_type[dep.type].insert(dep);
  }
  
  inline void add_edge(II a, DEP b) { 
    //assert(nodes.find(a) != nodes.end());
    //assert(nodes.find(b.ii) != nodes.end());
    edges.insert(EDGE(a, b.ii, b.type));
    to_neighbors[a].insert(b.ii);
    from_neighbors[b.ii].insert(a);
  }

  inline void add_node(II a) { 
    //assert(nodes.size() == 0 || depends_on(a));
    nodes.insert(a);
    for (pair<II,DEP> p : missing_deps[a]) {
        add_edge(p.first, p.second);
        missing_deps_for_node[p.first].erase(p.second);
        missing_deps_by_type[p.second.type].erase(p.second);
    }
    missing_deps.erase(a);
  }

  inline void add_node_deps(II node, const DEPENDENCY& deps) {
    //assert(nodes.find(node) != nodes.end());
    //assert(missing_deps_for_node.find(node) == missing_deps_for_node.end());
    for(const DEP *d = &(deps.dependencies[0]); d != &(deps.dependencies[deps.ndep]); d++) {
      add_dep(node, *d);
    }
  }

public:
  inline size_t nodes_size() { return nodes.size(); }
  inline size_t missing_deps_size() { return missing_deps.size(); }
  inline size_t missing_deps_size(DEP_TYPE d) { return missing_deps_by_type[d].size(); }

  void add_node_and_deps(II node, const DEPENDENCY& deps) {
    add_node(node);
    add_node_deps(node, deps);
  }

  void merge(const DepGraph& other) {
    for (II node : other.nodes) {
      //assert(!depends_on(node));
      nodes.insert(node);
    }

    edges.insert(other.edges.begin(), other.edges.end());

    map<II, set<II>>::const_iterator it_n;
    for(it_n = other.to_neighbors.begin(); it_n != other.to_neighbors.end(); it_n++) {
      to_neighbors[it_n->first].insert(it_n->second.begin(), it_n->second.end());
    }
    for(it_n = other.from_neighbors.begin(); it_n != other.from_neighbors.end(); it_n++) {
      from_neighbors[it_n->first].insert(it_n->second.begin(), it_n->second.end());
    }

    map<II, set<pair<II,DEP>>>::const_iterator it;
    for (it = other.missing_deps.begin(); it != other.missing_deps.end(); it++) {
      for (pair<II,DEP> p : it->second)
        add_dep(p.first, p.second);
    }
  }

  inline bool contains_node(II a) const { return nodes.find(a) != nodes.end(); }

  inline uint64_t depends_on(II a) const {
    map<II, set<pair<II, DEP>>>::const_iterator it = missing_deps.find(a);
    if(it == missing_deps.end())
      return 0;
    else
      return it->second.size();
  }

  // List of nodes already in this graph that depend on a via a given dep type.
  inline void get_depends_on_list(II a, DEP_TYPE type_of_dep, set<DEP>& fill_me) const {
    map<II, set<pair<II, DEP>>>::const_iterator it = missing_deps.find(a);
    if(it == missing_deps.end())
      return;
    for(pair<II, DEP> p : it->second) 
    {
      if(p.second.type == type_of_dep)
      {
        DEP d = {p.first, p.second.type, p.second.value, {p.second.addr}};  
        fill_me.insert(d);
      }
    }
  }

  inline uint64_t depends_on(II a, DEP_TYPE type_of_dep) const {
    set<DEP> s;
    get_depends_on_list(a, type_of_dep, s);
    return s.size();
  }

  inline uint64_t depends_on_indirect(II a, DEP_TYPE type_of_dep) const {
    set<DEP> s;
    get_depends_on_list(a, type_of_dep, s);
    // All nodes in s depend on this missing node a
    set<II> ret;
    stack<II> added;
    for(DEP d : s) {
      ret.insert(d.ii);
      added.push(d.ii);
    }   
    while(!added.empty())
    {
      II n = added.top();
      added.pop();
      map<II, set<II>>::const_iterator it = from_neighbors.find(n);
      if(it != from_neighbors.end()) {
        for(II fn : it->second) {
          if(ret.find(fn) == ret.end()) {
            ret.insert(fn); // anyone who points to n is added
            added.push(fn);
          }
        }
      }
    }
    return ret.size();
  }

  inline bool node_has_missing_deps(II a) const {
    map<II, set<DEP>>::const_iterator it = missing_deps_for_node.find(a);
    return it != missing_deps_for_node.end() && !it->second.empty();
  }

  inline bool node_is_sink(II a) const {
    map<II, set<II>>::const_iterator it = to_neighbors.find(a);
    return it != to_neighbors.end() && it->second.empty();
  }
  
  inline bool node_is_source(II a) const {
    map<II, set<II>>::const_iterator it = from_neighbors.find(a);
    return it != from_neighbors.end() && it->second.empty();
  }

#ifdef PRINT_GRAPHS
friend void draw_graphs(vector<DepGraph*>&, string);
friend void draw_graphs_with_clust(vector<DepGraph*>&, string);
friend void draw_graphs_funcs(vector<DepGraph*>&, string);
#endif
};

#ifdef PRINT_GRAPHS
// forward decls so I can put the drawing stuff at the bottom :)
void draw_graphs(vector<DepGraph*>&, string);
void draw_graphs_with_clust(vector<DepGraph*>&, string);
void draw_graphs_funcs(vector<DepGraph*>&, string);
#endif

static inline bool do_heuristics_mem(const TRACEENTRY& e,
                       const DEPENDENCY& e_deps,
                       const DepGraph& graph,
                       DEP& d)
{
  // statistics to save
  static pair<uint64_t, TRACEENTRY> stat_largest_number_mem_deps = make_pair(0,e);
  // end stats
 
#ifdef INST_GUESS 
  if(e.inst != INST_GUESS) return false; 
#endif
 
  uint64_t tree_deps_on_e = graph.depends_on_indirect(e, MEM_DEP);
  
  if(tree_deps_on_e > stat_largest_number_mem_deps.first) 
  {
    set<DEP> mem_deps_on_e;
    graph.get_depends_on_list(e, MEM_DEP, mem_deps_on_e);
#if ONE_PATH_CHECK
    if(mem_deps_on_e.size() < 2) return false; // a "one dep" path... forget it.
#endif

    LOG(format("MEM largest_number_deps_sat = %lu -> %lx %lu\n") 
         % stat_largest_number_mem_deps.first
         % stat_largest_number_mem_deps.second.addr
         % stat_largest_number_mem_deps.second.inst);
    LOG(format("MEM %lu -> %lx %lu\n") 
         % tree_deps_on_e % e.addr % e.inst);

    bool all_heap_ptrs = true;
    ADDRINT mem = mem_deps_on_e.begin()->addr;
    ADDRINT val = mem_deps_on_e.begin()->value;
    for(DEP ed : mem_deps_on_e)
    {
#define compare ( ed.value == val && \
                  scanner->Addr_In_Heap(ed.value) && \
                  ed.addr == mem)
      all_heap_ptrs = all_heap_ptrs && (compare);
      if(!(compare)) {
       LOG(format("! %lx <%lu>\n") % ed.addr % ed.value);
       break;
      }
#undef compare
    }
    if (all_heap_ptrs) {
        // this instruction must write a heap ptr into memory and everyone uses it...
        // the whole bitch depends on where he reads it from.
        d.ii.addr = 0;
        for(const DEP *ed = &(e_deps.dependencies[0]); ed != &(e_deps.dependencies[e_deps.ndep]); ed++) {
          if(ed->type == REG_DEP && ed->value == val) {
            d = {{ed->ii.addr, 0}, REG_DEP, val, {ed->reg}};
            stat_largest_number_mem_deps = make_pair(tree_deps_on_e, e);
            return true;
          }
        }
        LOG("! Couldn't find source\n");
        return false;
    }
  }
  return false;
}

static inline bool do_heuristics_reg(const TRACEENTRY& e,
                       const DEPENDENCY& e_deps,
                       const DepGraph& graph,
                       DEP& d)
{
  // statistics to save
  static pair<uint64_t, TRACEENTRY> stat_largest_number_reg_deps = make_pair(0,e);
  // end stats

#ifdef INST_GUESS
  if(e.inst != INST_GUESS) return false;
#endif

  uint64_t tree_deps_on_e = graph.depends_on_indirect(e, REG_DEP);
  
  if(tree_deps_on_e > stat_largest_number_reg_deps.first) 
  {
    set<DEP> reg_deps_on_e;
    graph.get_depends_on_list(e, REG_DEP, reg_deps_on_e);
#ifdef ONE_PATH_CHECK
    if(reg_deps_on_e.size() < 2) return false; // a "one dep" path... forget it.
#endif

    LOG(format("REG largest_number_deps_sat = %lu -> %lx %lu\n") 
          % stat_largest_number_reg_deps.first
          % stat_largest_number_reg_deps.second.addr
          % stat_largest_number_reg_deps.second.inst);
    LOG(format("REG %lu -> %lx %lu\n") 
         % tree_deps_on_e % e.addr % e.inst);

    bool all_heap_ptrs = true;
    ADDRINT reg = reg_deps_on_e.begin()->reg;
    ADDRINT val = reg_deps_on_e.begin()->value;
    for(DEP ed : reg_deps_on_e) {
 #define compare ( ed.value == val && \
                  scanner->Addr_In_Heap(ed.value) && \
                  ed.reg == reg)
      all_heap_ptrs = all_heap_ptrs && (compare);
      if(!(compare)) {
       LOG(format("! %s<%lu>\n") % REG_StringShort((REG)ed.reg) % ed.value);
       break;
      }
#undef compare
    }
    if (all_heap_ptrs) {
      stat_largest_number_reg_deps = make_pair(tree_deps_on_e, e);
      d = {{e.addr, 0}, REG_DEP, val, {reg}};
      return true;
    }
  }
  return false;
}

static inline bool do_heuristics(const TRACEENTRY& e, const DEPENDENCY& e_deps,
                   const DepGraph& graph, DEP& d)
{
    if(do_heuristics_reg(e, e_deps, graph, d))
        return true;
    else if(do_heuristics_mem(e, e_deps, graph, d))
        return true;
    else
        return false;
}

static inline DepGraph& max_nodes_graph(const TRACEENTRY& e, const vector<DepGraph*>& graphs)
{
  DepGraph& ret = *(graphs[0]);
  for(DepGraph* g : graphs)
  {
    if(g->nodes_size() > ret.nodes_size())
        ret = *g;
  }
  return ret;
}

#define print_progress() \
  do { \
    LOG(format("\t%lu / %lu (%f%%)\tNumber of Independent Sets %d\n") \
         % (slice.size() - slice_index)    \
         % slice.size()    \
         % ((slice.size() - slice_index) / (double)slice.size() * 100)    \
         % graphs.size());  \
    if(AGGRESSIVE_LOGGING > 1) { \
      for (DepGraph* graph : graphs) {    \
        LOG(format("\t\t: %lu nodes %lu deps\n")    \
             % graph->nodes_size()    \
             % graph->missing_deps_size());   \
      }\
    }   \
  } while(0)

static inline set<DEP>
compute_closure(set<II>& initial_deps, 
                const vector<UINT64>& slice,
                const SLICETRACE& trace)
{
#define slice_percent() ((slice.size()-slice_index)/(double)slice.size()) 

  set<DEP> ret;
  vector<DepGraph*> graphs;

  LOG(" Building Graphs...\n");
  UINT64 slice_index = slice.size();
  UINT64 progress = 0;

  for (UINT64 i : slice) {
    // Step through each instruction entry in the slice
    TRACEENTRY& e = trace.entries[i];
    DEPENDENCY& dep = trace.get_dep(i);
    vector<DepGraph*> added_node;

    // If this is a node that MUST be in the closure (i.e. bcrit node)
    if (initial_deps.size() != 0) {
      set<II>::iterator it = initial_deps.find(e);
      if (it != initial_deps.end()) {
        // make a new graph for it...
        DepGraph* graph = new DepGraph;
        graph->add_node_and_deps(e, dep);
        added_node.push_back(graph);
        graphs.push_back(graph);
        initial_deps.erase(it);
      }
      if(initial_deps.size() == 0) {
        LOG(" Added Last Criterion\n");
        print_progress();
      }
    }
    
    // do some "heuristics" to add the dep's on e to the return set
    if(initial_deps.size() == 0 && e.addr != MODEL_INST_ADDR)
    {
      DEP d;
      if (do_heuristics(e, dep, max_nodes_graph(e, graphs), d))
      {
        LOG(format("Adding Guess: %lx %s\n") % d.ii.addr 
              % REG_StringShort((REG)d.reg));

#ifdef PRINT_GRAPHS
        draw_graphs_with_clust(graphs, 
          (format("draw_dep/guess%lu.dot") % ret.size()).str());
#endif
        ret.insert(d);
      }
    }

    // Check if any of the graphs need this node
    for (DepGraph* graph : graphs)
    {  
      if(graph->depends_on(e) > 0) 
      {
        graph->add_node_and_deps(e, dep);
        added_node.push_back(graph);
      }
    }

    // Do any of them need to be merged?
    if (added_node.size() > 1) {
      DepGraph* first = added_node.back();
      added_node.pop_back();
      for(DepGraph* other : added_node) {
        print_progress();
        LOG(" Merge\n");
        first->merge(*other);
        graphs.erase(find(graphs.begin(), graphs.end(), other));
        delete other;
        print_progress();
      }
#ifdef PRINT_GRAPHS
      draw_graphs_with_clust(graphs, 
        (format("draw_dep/%lu.clust.dot") % (slice->size() - slice_index)).str());
#endif
    }

    /* Try to break early? */
    double sp = slice_percent();
    if (sp > (SLICE_INCLUDE_RATIO)/2)
    {
      bool can_break = graphs.size() > 0 && initial_deps.size() == 0;
      for(DepGraph* graph : graphs) {
          can_break = can_break && (graph->missing_deps_size() == 0);
      }
      if(can_break || sp > (SLICE_INCLUDE_RATIO))
      {
        print_progress();
        LOG(format("Stopped on Inst: %lx:%d\n") % e.addr % e.inst);
        for(DepGraph* graph : graphs) {
          delete graph;
        }
        break;
      }
    }
    
    if (++progress >= 100) {
      print_progress();
      progress = 0;
    }

    slice_index--;  
  }

#ifdef PRINT_GRAPHS
  draw_graphs(graphs, "draw_dep/final.dot");
  draw_graphs_with_clust(graphs, "draw_dep/final.clust.dot");
  draw_graphs_funcs(graphs, "draw_dep/final.funcs.dot");
#endif

  return ret;
#undef slice_percent
}

static inline vector<UINT64> load_slice(const string& path)
{
  vector<UINT64> ret;
  LOG(format("Loading slice from %s\n") % path.c_str());
  FILE* fp = fopen(path.c_str(), "rt");
  if (!fp) return ret;

  UINT64 temp;
  while (fscanf(fp, "%lu", &temp) == 1) {
    ret.push_back(temp);
  }
  
  LOG(format("  %lu dependencies loaded\n") % ret.size());
  fclose(fp);
  return ret;
}

static inline set<II> load_dependencies(const string& path)
{
  set<II> ret;
  FILE* fp = fopen(path.c_str(), "rt");
  if (!fp) return ret;

  LOG(format("Loading dependencies from %s\n") % path.c_str());

  II temp;
#define BUF_SZ (1024)
  char buffer[BUF_SZ];
  memset(buffer, 0, BUF_SZ);
  while (fgets(buffer, BUF_SZ, fp)) {
    sscanf(buffer, "%p %lu", (void**)&temp.addr, &temp.instance);
    ret.insert(temp);
    memset(buffer, 0, BUF_SZ);
  }
#undef BUF_SZ
  LOG(format("  %lu dependencies loaded\n") % ret.size());
  fclose(fp);
  return ret;
}


vector<ClosurePoint>
Make_Guesses(const string& analysis_directory, PIN_Scan* s,
             double percent, const PIN_Address_Translator& trans)
{
#ifdef PRINT_GRAPHS
  system(("mkdir -p "+analysis_directory+"/../draw_dep").c_str());
#endif

  scanner = s;

  DEBUG_INFO.Import(analysis_directory+"/../"+DEBUG_FILE_NAME);
  set<II> bcrit = load_dependencies(analysis_directory+ "/../bcrit");

  SLICE_INCLUDE_RATIO = percent;

  SLICETRACE trace;
  trace.Import(analysis_directory);

  string basename = trace.directory + "/" + trace.directory + ".";

  vector<UINT64> slice = load_slice(basename + "slice");
  
  set<DEP> closure = compute_closure(bcrit, slice, trace);
  vector<ClosurePoint> ret;
  for(DEP d : closure) {
    if(d.ii.addr != MODEL_INST_ADDR) {
      ret.push_back(ClosurePoint(d, trans));
    }
  }
  return ret;
}

vector<ClosurePoint>
TryFindGuessFile(const string& analysis_dir)
{
  vector<ClosurePoint> ret;
#ifdef SAVE_GUESSES
  FILE *gf = fopen((analysis_dir+"/guesses.out").c_str(), "rt");
  if(gf == NULL) { return ret; }
#define BUFF_SZ (1024)
  char line[BUFF_SZ];
  while(fgets(line, 1024, gf) != NULL) {
    ret.push_back(ClosurePoint(line));
  }
  fclose(gf);
#endif
  return ret;
}

VOID 
OutputGuessFile(const string& analysis_dir, const vector<ClosurePoint>& guesses)
{
#ifdef SAVE_GUESSES
  FILE *gf = fopen((analysis_dir+"/guesses.out").c_str(), "wt");
  for(ClosurePoint c : guesses) {
    if(!c.done)
      fputs((c.ToString() + "\n").c_str(), gf);
  }
  fclose(gf);
#endif
}


#ifdef PRINT_GRAPHS

/*********** GRAPHING STUFF ********************/
#define get_debug_info(II) \
    DEBUG_INFO.get((II).addr, ((II).addr == MODEL_INST_ADDR ? (II).instance : 0))

inline string make_label(II node)
{
  const DBG& d = get_debug_info(node);
  return (format("(0x%lx:%d) %s <%s>") 
           % node.addr 
           % node.instance
           % d.assembly
           % d.rtnname).str();
}

inline string node_to_dot(II node, uint64_t node_id, DepGraph* graph)
{
  return (format("%lu [label=\"%s\" %s];\n")
           % node_id
           % make_label(node)
           % (graph->node_has_missing_deps(node) ? "color=red" : 
              (graph->node_is_sink(node)         ? "color=blue": "")) ).str();
}

inline string get_edge_color(DepGraph::EDGE edge)
{
  if(edge.type == CONTROL_DEP)
    return "[color=red]";
  else if (get_debug_info(edge.source).rtn != get_debug_info(edge.dest).rtn)
    return "[color=blue]";
  else
    return "";
}

inline string edge_to_dot(DepGraph::EDGE edge, map<II, uint64_t>& ids_map)
{
  return (format("%lu -> %lu %s;\n")
           % ids_map[edge.source]
           % ids_map[edge.dest]
           % get_edge_color(edge)).str();
}


void draw_graphs_with_clust(vector<DepGraph *>& graphs, string filename)
{
  FILE* fp = fopen(filename.c_str(), "w");
  if (!fp) {
    LOG("Could not output: " + filename + "\n");
    return;
  }
  fprintf (fp, "digraph {\n");
  
  map<uint64_t, string> func_to_edges_string;
  map<II, uint64_t> node_to_ids;
  uint64_t node_id = 0;

  for(DepGraph *graph : graphs) {
    for(II node : graph->nodes) {
      uint64_t id = node_id++;
      node_to_ids[node] = id;
      fprintf(fp, "%s", node_to_dot(node, id, graph).c_str());
    }

    for(DepGraph::EDGE edge : graph->edges) {
      string edge_string = edge_to_dot(edge, node_to_ids);

      const DBG& d_source = get_debug_info(edge.source);
      if(d_source.rtn == get_debug_info(edge.dest).rtn)
        func_to_edges_string[d_source.rtn] += edge_string;
      else
        fprintf(fp, "%s", edge_string.c_str());
    }
  }

  map<uint64_t, string>::iterator it = func_to_edges_string.begin();
  for(; it != func_to_edges_string.end(); it++) 
    fprintf(fp, "subgraph cluster_%lx {\n label=%s;\n%s}\n",
            it->first, DEBUG_INFO.get(it->first, 0).rtnname.c_str(), it->second.c_str());

  fprintf (fp, "}\n");
  fclose(fp);
}

void draw_graphs_funcs(vector<DepGraph *>& graphs, string filename)
{
  FILE* fp = fopen(filename.c_str(), "w");
  if (!fp) {
    LOG("Could not output: " + filename +"\n");
    return;
  }
  fprintf (fp, "digraph {\nconcentrate=true\n");

  map<uint64_t, string> all_rtns;
  map<uint64_t, string> func_edges;

  for(DepGraph* graph : graphs) {
    for(DepGraph::EDGE edge : graph->edges) {
        const DBG& d_source = get_debug_info(edge.source);
        const DBG& d_dest = get_debug_info(edge.dest);
        if(d_source.rtn != d_dest.rtn) {
#define add(d) \
  if(all_rtns.find(d.rtn) == all_rtns.end()) { \
    all_rtns[d.rtn] = (format("%ld [label=\"%s\"") % d.rtn % d.rtnname ).str(); \
  }
          add(d_source);
          add(d_dest);
          func_edges[d_source.rtn] += (format("%ld -> %ld;") % d_source.rtn % d_dest.rtn).str();
      }
    }
  }

  map<uint64_t, string>::iterator it = all_rtns.begin();
  for(; it != all_rtns.end(); it++) {
    fprintf(fp, "%s", it->second.c_str());
    if(func_edges.find(it->first) == func_edges.end())
      fprintf(fp, " color=blue"); // sink!
    fprintf(fp, "];\n");    
  }


  it = func_edges.begin();
  for(; it != func_edges.end(); it++)
    fprintf(fp, "%s\n", it->second.c_str());

 
  fprintf (fp, "}\n");
  fclose(fp);
}

void draw_graphs(vector<DepGraph *>& graphs, string filename)
{
  FILE* fp = fopen(filename.c_str(), "w");
  if (!fp) {
    LOG("Could not output: " + filename +"\n");
    return;
  }
  fprintf (fp, "digraph {\n");
  
  uint64_t node_id = 0;
  map<II, uint64_t> node_to_ids;
  for(DepGraph *graph : graphs) { 
    for(II node : graph->nodes) {
      uint64_t id = node_id++;
      node_to_ids[node] = id;
      fprintf(fp, "%s", node_to_dot(node, id, graph).c_str());
    }

    for(DepGraph::EDGE edge : graph->edges) {
      fprintf(fp, "%s", edge_to_dot(edge, node_to_ids).c_str());
    }
  }
 
  fprintf (fp, "}\n");
  fclose(fp);
}

#endif

