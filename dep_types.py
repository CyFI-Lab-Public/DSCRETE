##
# This is file is included in several other python scripts which have to parse 
#  the output of pin_slicer
##

class dep:
  MODEL_ADDR = 0x800000000
  def __init__(self, string):
    string = string.split();
    self.addr = int(string[0], 16)
    self.inst = int(string[1], 10)
    self.dep_type = string[2]
    if self.dep_type == "MEM_DEP":
      self.dep_addr = int(string[3], 16)
      self.dep_val = int(string[4], 16)
      self.str_val = " ".join(string[5:])
    elif self.dep_type == "REG_DEP":
      self.reg = int(string[3], 10)
      self.reg_str = string[4]
      self.dep_val = int(string[5], 16)
      self.str_val = " ".join(string[6:])

  def __eq__(self, other):
    ret = self.addr == other.addr and \
          self.inst == other.inst and \
          self.dep_type == other.dep_type
    if not ret or self.dep_type == "CONTROL_DEP":
       return ret
    if self.dep_type == "MEM_DEP":
      ret = self.dep_addr == other.dep_addr
    else: # self.dep_type == "REG_DEP"
      ret = self.reg == other.reg and \
            self.reg_str == other.reg_str
    return ret and \
           self.dep_val == other.dep_val and \
           self.str_val == other.str_val
           
  def __hash__(self):
    return hash(self.addr+self.inst)+hash(self.dep_type)

  def __str__(self):
    ret = hex(self.addr)+" "+str(self.inst)+" "+self.dep_type+" "
    if self.dep_type == "MEM_DEP":
      ret = ret + hex(self.dep_addr)
    elif self.dep_type == "REG_DEP":
      ret = ret + str(self.reg) + " " + self.reg_str
    else:
      return ret + "CONTROL_DEP"
    ret = ret + " " + hex(self.dep_val) + " " + self.str_val
    return ret

  def is_model(self):
    return self.addr == dep.MODEL_ADDR
    

class write_ent:
  @staticmethod
  def parse(string):
    sides = string.split("|")
    left = sides[0].split(":")
    right = sides[1].split(":")
    return {left[0].strip():left[1].strip(), \
            right[0].strip():right[1].strip()}

  @staticmethod
  def clean_line(line):
    if line[0:4] == "RET ":
      return ""
    index = line.find("0x");
    if index == -1:
      return ""
    return line[index:].strip()
  

  def __init__(self, strings):
    p = self.parse(strings[0])
    self.routine = p["Routine"]
    self.img = p["Img"]
    strings.pop(0)
    p = self.parse(strings[0])
    self.addr = int(p["Address"], 16)
    self.inst = int(p["Inst"], 10)
    strings.pop(0)
    if "Info File" in strings[0]:
      p = self.parse(strings[0])
      self.info_file = p["Info File"]
      self.dump_file = p["Dump File"]
      strings.pop(0)
    self.all_deps = set([dep(line) for line in \
                           (self.clean_line(s) for s in strings) \
                          if len(line) > 0])
    while strings[0] != "=== Others\n":
      s = strings[0].split()
      if s[0] == "RET":
        self.ret = int(s[1], 16)
      elif s[0] == "ARG":
        if not hasattr(self, "args"):
          self.args = dict()
        arg_index = int(s[1])
        self.args[arg_index] = set()
        self.args[arg_index].add(dep(self.clean_line(strings[0])))
      else:
        self.args[arg_index].add(dep(self.clean_line(strings[0])))
      strings.pop(0)

  def get_arg_hint(self, deps):
    if "va_list" in self.routine:
      return "Hint: Looks like va_list args! " + \
             "Suggest \"#?va#?\" First #? is format, " + \
             "Second #? is va_list (Args start at 0!)."

    if "gdk_pixbuf" in self.routine:
      return "Hint: Looks like gdk_pixbuf args! " + \
             "Suggest \"#?p\". #? is the pixbuf arg (Args start at 0!)."

    for i, a in self.args.iteritems():
      inter = deps & a
      if len(inter) > 0:
        return "Hint: Arg "+str(i)+" matches! Suggest: \""+str(i)+ \
               "s\" OR \""+str(i)+"r\" OR \""+str(i)+"a#?\" "+ \
               "#? is the number of the length arg (Args start at 0!)."

    return "Hint: Could not find matching arg :("

class translator:
  class img_info:
    def __init__(self, start, length, name):
      self.start_addr = start
      self.end_addr = start+length
      self.name = name

  def __by_addr(self, addr):
    for info in self.img_list:
      if info[1].end_addr >= addr:
        if info[1].start_addr <= addr:
          return info[1]
        return None
    return None
       
  def __init__(self, meminfo_filename):
    self.img_list = []
    with open(meminfo_filename, "r") as f:
      for line in f:
        line = line.strip().split()
        if '[' in line [0]:
          continue
        if '!' == line[0][0]:
          line[0] = line[0][1:]
        if "^scan^" in line[0:5]:
          line[0] = line[0][5:]
        line[1] = line[1].split("->")
        start = int(line[1][0], 16)
        length = int(line[1][1])
        pair = (start+length, translator.img_info(start, length, line[0]))
        self.img_list.append(pair)
    sorted(self.img_list, key=lambda info: info[0])

  def translate(self, addr):
    i = self.__by_addr(addr)
    if i is not None:
      return (addr - i.start_addr, i.name)
    return None

