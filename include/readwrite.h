#ifndef _READWRITE_H_
#define _READWRITE_H_

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>

template <class T>
inline void WRITE(FILE* fp, const T& val) {
  assert (fwrite (&val, sizeof(val), 1, fp) == 1);
}

template <class T>
inline T READ(FILE* fp) {
  T var;
  assert (fread(&var, sizeof(T), 1, fp) == 1);
  return var;
}

inline void ASSERT_EMPTY(FILE* fp) {
  char var;
  assert (fread(&var, 1, 1, fp) == 0);
}

inline bool EXISTS(const std::string& filename) {
  return access(filename.c_str(), F_OK) == 0;
}

#endif
