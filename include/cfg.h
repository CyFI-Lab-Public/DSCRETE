#ifndef CFG_H
#define CFG_H

#include <cassert>
#include <map>

#include "readwrite.h"
#include "btree/btree_set.h"
#include "forensix_slicing_constants.h"
#include "pin_types.h"
#include "output.h"
#include "errno.h"

class CFG 
{
public:
  struct Node {
    ADDRINT addr = 0;
    btree::btree_set<Node*> succ;
    btree::btree_set<Node*> pred;
    btree::btree_set<Node*> pdom;
    Node* ipdom = 0;
  };

protected:
  Node* prev_Node = 0;
  std::map<ADDRINT, Node> nodes;
  bool valid = true;

public:
  int Nodes() { return nodes.size(); }
  Node& Find(ADDRINT pc) { assert (nodes.find(pc) != nodes.end()); return nodes[pc]; }
  BOOL IsValid() { return valid; }

  VOID Export(const char* filename)
  {
    FILE* f = fopen(filename, "wb");
    if(f == NULL) {
      LOG(format("fopen: %s") % strerror(errno));
      return;
    }
    WRITE<UINT64>(f, nodes.size());
  
    for (auto & I : nodes) {
      Node& n = I.second;
      assert (I.first == n.addr);
  
      WRITE<UINT64>(f, n.addr);
      WRITE<UINT64>(f, n.ipdom ? n.ipdom->addr : 0);
      WRITE<UINT64>(f, n.succ.size());
  
      for (Node * s : n.succ) {
        assert (s);
        WRITE<UINT64>(f, s->addr);
      }
    }
    fclose(f);
    LOG(format("CFG export: %d nodes\n") % nodes.size());
  }
  
  VOID Import(const char *filename)
  {
    FILE* f = fopen(filename, "rb");
    if (!f) { 
      LOG(format("CFG: %s Not Found\n") % filename);
      return;
    }
  
    UINT64 cnt = READ<UINT64>(f);
  
    LOG(format("CFG Nodes: %lu\n") % cnt);
  
    for (UINT64 i = 0; i < cnt; i++) {
      UINT64 addr = READ<UINT64>(f);
      UINT64 ipdom = READ<UINT64>(f);
  
      assert (addr != 0);
  
      Node& n = nodes[addr];
      n.addr = addr;
      n.ipdom = ipdom == 0 ? NULL : &nodes[ipdom];
  
      UINT64 nsucc = READ<UINT64>(f);
      for (UINT64 j = 0; j < nsucc; j++) {
        UINT64 s = READ<UINT64>(f);
        n.succ.insert(&nodes[s]);
      }
  
      if (n.addr != EXIT_INST_ADDR)
        valid = valid && (n.ipdom != NULL);
    }
    ASSERT_EMPTY(f);
    fclose(f);
  
    for (auto & I: nodes) {
      Node& n = I.second;
      for (Node * s : n.succ) {
        assert(s);
        assert(&n != s);
        s->pred.insert(&n);
      }
    }
  
    if (valid)
      LOG("CFG IS VALID at IMPORT\n");
    else
      LOG("CFG IS NOT VALID at IMPORT\n");
  }
};
#endif
