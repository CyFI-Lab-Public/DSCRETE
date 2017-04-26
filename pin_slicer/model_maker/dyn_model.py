from pygccxml.declarations.cpptypes import void_t
from pygccxml.declarations.type_traits import is_void, is_floating_point

class model_info(object):
  def __init__(self, name, n_params):
    self.__name = name
    self._n_params = n_params

  def get_name(self):
    return self.__name

  def __eq__(self, other):
    return self.__name == other.__name and \
           (self._n_params == None or \
            other._n_params == None or \
            self._n_params == other._n_params)
  def __hash__(self):
    return hash(self.__name)


class model(object):
  def __init__(self, call_decl ):
    self.__call_decl = call_decl
    self.__ctxt = ""
  
  def __str__(self):
    return self.get_ret_type_str() + " " + \
           str(self.get_n_params()) + " " + \
           str(1 if self.get_has_ellips() else 0) + \
           ("\n" + self.get_params_str() if self.get_n_params() > 0 else "")

  def get_params_str(self):
    ret = ""
    for i, arg in enumerate(self.__call_decl.arguments):
      if arg.ellipsis:
        continue
      ret = ret + "\n" + str(i) + " "
      if is_floating_point(arg):
        ret = ret + "f "
      else:
        ret = ret + "i "
      ret = ret + str(arg.name)
    return ret.strip()

  def get_ret_type_str(self):
    if not self.get_has_return():
      return "v"
    elif is_floating_point(self.__call_decl.return_type):
      return "f"
    else:
      return "i"

  def get_n_params(self):
    ret = len(self.__call_decl.arguments)
    if self.get_has_ellips():
      ret = ret - 1
    return ret

  def get_name(self):
    return self.__call_decl.name

  def get_has_ellips(self):
    return self.__call_decl.has_ellipsis

  def get_has_return(self):
    return self.__call_decl.return_type != None and \
           not is_void(self.__call_decl.return_type)

  def append_ctxt(self, string):
    self.__ctxt = string+"::"+self.__ctxt

  def get_full_name(self):
    return self.__ctxt+self.get_name()

  def get_model_info(self):
    return model_info(self.get_full_name(), self.get_n_params())
