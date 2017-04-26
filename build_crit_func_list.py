#!/usr/bin/pypy

####
# Builds a "build_scanner.info" file from
# the chosen bcrit and __write.out files.
####

import sys
from itertools import groupby
from dep_types import dep, write_ent, translator

def err_out(err_str):
  print err_str+"\n"
  exit()

if len(sys.argv) > 5 or len(sys.argv) < 5:
  err_out(sys.argv[0]+" [bcrit file] [__write file] [address translation file] [output file]")

trans = translator(sys.argv[3])

with open(sys.argv[1], 'r') as bcrit_file:
  bcrit_elems = set([dep(line) for line in bcrit_file])

sep_string = "=================================================\n"
with open(sys.argv[2], 'r') as write_file:
  write_list = [w for w in \
                 (write_ent(list(group)) for k, group in \
                   groupby(write_file.readlines(), lambda x: x==sep_string) \
                 if not k) \
               if len(w.all_deps & bcrit_elems) > 0]

if len(write_list) == 0:
  err_out("Are you sure your input files are right? No matching deps!")

chosen_funcs = list({w.addr: w for w in write_list}.values())

with open(sys.argv[4], 'w') as out_file:
  for c in chosen_funcs:
    offset, img = trans.translate(c.addr)
    out_file.write(hex(offset)+" "+img+"\n"+c.get_arg_hint(c.all_deps & bcrit_elems)+"\n"+c.routine+"\n")

if len(chosen_funcs) == 1 and hasattr(chosen_funcs[0], "info_file"):
  print "Info File: "+chosen_funcs[0].info_file+" Dump File: "+chosen_funcs[0].dump_file+"\n"
