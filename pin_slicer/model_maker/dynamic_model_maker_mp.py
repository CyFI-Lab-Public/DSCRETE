#!/usr/bin/pypy

import os
import string
import copy
import logging
import warnings
from subprocess import Popen, PIPE
from multiprocessing import Pool, Manager
import sys
from dyn_model import model_info, model
from pygccxml import parser, declarations
from pygccxml.declarations.namespace import namespace_t
from pygccxml.declarations.class_declaration import class_t
from pygccxml.declarations.calldef import calldef_t

# Shut up the NOISY pygccxml module!
logging.disable(100)
warnings.filterwarnings("ignore")

############################################################
def popen_helper(cmd):
  proc = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, close_fds=True)
  output = proc.stdout.read()
  proc.stdout.close()
  proc.stderr.close()      
  return output, proc.wait()

def import_files():
  ret = dict()
  for root, dirnames, filenames in os.walk('/usr/include'):
    for filename in filenames:
      if filename[-2:] == ".h" or filename[-4:] == ".hxx":
        ret[os.path.join(root,filename)] = None
  return ret

############################################################

known_models = Manager().dict()
remaining_files = import_files()

def build_model_str(find_model_info, lib):
  global known_models
  try:
    ret_str = known_models[find_model_info]
  except KeyError:
    ret_str = check_files_for(find_model_info, lib)
    if ret_str == "":
      ret_str = "Cannot Find:"+find_model_info.get_name()+"@"+lib
  return ret_str

########################################################
def get_pkg_config_name_for(img_name):
  pkgs, code = popen_helper("pkg-config --list-all | awk '{ print $1 }'")
  pkgs = pkgs.split()
  for pkg in pkgs:
    lib_flags, code2 = popen_helper("pkg-config --libs " +pkg)
    libs = ["lib"+s[2:]+".so" for s in lib_flags.split()]
    if img_name in libs:
      return pkg

def get_cpp_flags_for(img_name):
  flags = []
  pkg = get_pkg_config_name_for(img_name)
  if pkg != None:
    flags_str, code = popen_helper("pkg-config --cflags "+pkg)
    flags = flags_str.split()
    try:
     flags.remove("-pthread")
    except ValueError:
      pass
  return flags


########################################################
def parse_namespace(ns):
  models = parse_decls(ns.declarations)
  for m in models:
    m.append_ctxt(ns.name)
  return models 

def parse_class(cl):
  models = parse_decls(cl.declarations)
  for m in models:
    m.append_ctxt(cl.name)
  return models 
 
def parse_decls(decls):
  models = []
  for decl in decls:
    if type(decl) is namespace_t:
      models = models + parse_namespace(decl)
    elif type(decl) is class_t:
      models = models + parse_class(decl)
    elif issubclass(type(decl), calldef_t):
      models.append(model(decl))
  return models

def process_get_result(args):
  global known_models
  file_name = args[0]
  cpp_flags = args[1]
  previous_flags = args[2]

  parser_cpp_flags = " -D\'__deprecated__(s)=__deprecated__\' -D_GNU_SOURCE -P -O3" + \
                     " -I/usr/lib/gcc/x86_64-linux-gnu/4.7 -I/usr/lib/gcc/x86_64-linux-gnu/4.7/include" + \
                     " -I/usr/include/x86_64-linux-gnu " + " ".join(cpp_flags)
  config = parser.config_t( cflags=parser_cpp_flags )
  try:
    decls = parser.parse( [file_name], config )
  except parser.source_reader.gccxml_runtime_error_t as e:
    return (False, file_name, previous_flags, cpp_flags)
  
  target_model = args[3]
  found = ""
  decls = declarations.get_global_namespace(decls).declarations
  models = parse_decls(decls)
  for m in models:
    m_info = m.get_model_info()
    m_str = str(m)
    known_models[m_info] = m_str
    if m_info == target_model:
      found = m_str

  return (True, file_name, found)

########################################################


pool = Pool(processes=12)
def check_files_for(target_model, lib):
  global remaining_files
  global pool
  cpp_flags = set(get_cpp_flags_for(lib))
  args = []
  for file_name, previous_flags in list(remaining_files.items()):
    if previous_flags is None or \
       (len(cpp_flags) > 0 and not previous_flags.issuperset(cpp_flags)):
      args.append([file_name, cpp_flags, previous_flags, target_model])

  p_returns = pool.map(process_get_result, args)
  ret_str = ""
  for p_ret in p_returns:
      if p_ret[0] == True:
        del remaining_files[p_ret[1]]
        if p_ret[2] != "" and ret_str == "":
          ret_str = p_ret[2]
      else: # == False
        if p_ret[2] is None:
          remaining_files[p_ret[1]] = p_ret[3].copy()
        else:
          remaining_files[p_ret[1]] |= p_ret[3]
  return ret_str


########################################################
def count_params(param_str):
  start = 0
  while not "(" == param_str[start]:
    start = start + 1
    if start == len(param_str):
      raise IndexError
  parenths = []
  count = 0
  param_string = ""
  for c in param_str[start: ]:
    if c == ',' and len(parenths) == 1:
      if param_string != "void":
        count = count + 1
      param_string = ""
    elif c == '(':
      parenths.append('(')
    elif c == ')':
      parenths.pop()
      if len(parenths) == 0:
        if param_string != "void":
          count = count + 1
        break
    elif len(parenths) > 0:
      param_string += c
  else: # for ... else lolz
    raise IndexError
  return count

########################################################
# Loop on input
stuff = sys.stdin.readline().strip()
while stuff != "QUIT":
  stuff = stuff.split("@")
  name = stuff[0]
  lib = stuff[1]
  if name[0:2] == "_Z":
    cpp_name, code = popen_helper("c++filt -p "+name)
    args, code = popen_helper("c++filt "+name)
    name = cpp_name.strip()
    args = args[len(name)-1:]
    n_args = count_params(args)
    this_model = model_info(name, n_args)
  else:
    this_model = model_info(name, None)
  print name+"@"+lib # echo input
  stuff = build_model_str(this_model, lib)
  print stuff
  sys.stdout.flush()
  stuff = sys.stdin.readline().strip()

print "Bye!\n"


