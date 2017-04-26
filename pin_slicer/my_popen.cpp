#include <string.h>
#include <string>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <sched.h>
#include <libgen.h>
#include "my_popen.h"

using namespace std;

Pipes open_pipes(string path)
{
  static string script_path = path;
  int to_child[2];
  int from_child[2];

  pipe(to_child); // Where the parent is going to write to
  pipe(from_child); // From where parent is going to read

  if(!fork())
  {
    setvbuf(stdout,NULL,_IOLBF,0);
    setvbuf(stderr,NULL,_IOLBF,0);
    setvbuf(stdin,NULL,_IOLBF,0);

    close(from_child[0]); // close reading side of from_child
    dup2(from_child[1], STDOUT_FILENO);
    dup2(from_child[1], STDERR_FILENO);

    close(to_child[1]); // close stdin
    dup2(to_child[0], STDIN_FILENO);
    execl(script_path.c_str(), script_path.c_str(), (char*) NULL);
  }
  
  close(from_child[1]); // close writing side of out
  close(to_child[0]); // close reading side of in

  Pipes ret = {fdopen(to_child[1], "w"), fdopen(from_child[0], "r")};
  setvbuf(ret.input,NULL,_IOLBF,0);
  setvbuf(ret.output,NULL,_IOLBF,0);
  return ret;
}
