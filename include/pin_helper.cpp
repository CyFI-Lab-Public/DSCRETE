#include "pin_helper.h"

set<string> _blacklist_ =
  {".plt", "stat", "fstat", "lstat",
   "__stat", "__fstat", "__lstat", "stat64", "fstat64", "lstat64"};

set<string> _whitelist_ =
  {"libpurple",
   "/lib/pidgin/",
   "/lib/purple-2/",
   "libempathy",
   "/lib/gthumb/extensions/",
   "libMagickCore.so",
   "libMagickWand.so",
   "libpoppler.so"
  };

