#ifndef OUTPUT_H
#define OUTPUT_H

#include <string>

#undef LOG
#include <boost/format.hpp>
using boost::format;

#ifdef FORENSIX_SLICING
  static inline void LOG(const std::string& str) { QMESSAGE(MessageTypeLog, str); }
#else
  static inline void LOG(const std::string& str) { puts(str.c_str()); }
#endif

static inline void LOG(const boost::basic_format<char>& fmt){ LOG(fmt.str()); }

#endif // OUTPUT_H
