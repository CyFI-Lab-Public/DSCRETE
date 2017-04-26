
#include <stdio.h>
#include <stdlib.h>
#include <string>

struct Pipes {
  FILE* input;
  FILE* output;
};

Pipes open_pipes(std::string path);
