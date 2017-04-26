## DSCRETE: Automatic Rendering of Forensic Information from Memory Images via Application Logic Reuse

 Brendan Saltaformaggio

### Foreword:
Please remember that this is a research prototype and thus you
*should* expect to change makefile variables, dig through source
code for error messages, and find some corner-case that I forgot
to mention in this README. Before trying to use this tool, you
should be very familiar with the 
[DSCRETE paper](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-saltaformaggio.pdf).
That said, I welcome any questions, comments, or suggestions --- feel free
to email me. :)

To help anyone who wants to try to use DSCRETE, I have also included a
full test case with step-by-step instructions in dscrete_VM.tar.gz
(available for download on my website under Publications).
I verified that this test worked on my system before uploading it
with the DSCRETE source code. Note: You should be very familiar
with the
[DSCRETE paper](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-saltaformaggio.pdf)
and this README before trying to run DSCRETE.


### Requirements:
Pin Binary Analysis Framework - The tool was
 developed with Pin version 2.13, and not tested
 with any other versions.

Boost C++ libraries (on Linux: apt-get install libboost-all-dev)

Pypy python interpreter - or you can change all my python scripts to
use whatever interpreter you want.

vim - Some scripts assume you have it installed.

ASLR must be disabled to operate this tool.

The system was developed on a Ubuntu 12.10 Linux box. It has
not been tested on other environments. I suspect similar Linux
versions will be safe, but may require some tweaks to the
code base. 


### Building the system:
There are three programs which need to be compiled: pin_slicer,
analysis, and pin_scanner. Each of these are in their own directory
and have their own makefiles. You *should* look at the makefiles
before you try to build. You will likely need to change
the "PIN" variable to point to your installation of Pin.

Successfully building each program should result in the
following binary files:

pin_slice/libforensixslicing.so: This is a Pin tool
which collects a dynamic trace of the binary you want
to investigate. 

analysis/analysis: This is a standard C++ program which
processes the output files of the pin_slicer to compute
an execution slice based on some backward slicing criteria.

pin_scanner/libforensixscanner.so: This is a Pin tool which
uses the backward slice to either 1) build a scanner+renderer tool
or 2) use an input scanner+renderer tool to scan a memory image.

A note on libforensixscanner.so:
For simplicity, both Building a Scanner+Renderer Tool (Step 3
below) and Memory Image Scanning (Step 4) use the same code base.
That code is in the pin_scanner directory. You control which Pin tool
gets built via a macro at the top of the file pin_forensix_scanner.cpp.

If BUILD_SCANNER is defined, then the code will build into the 
Scanner+Renderer Builder. This is used in Step 3 to extract a
scanner definition file from your input binary.

If BUILD_SCANNER is *not* defined, then the code builds into the
Scanner+Renderer framework. The Scanner+Renderer framework 
takes the scanner definition file you built in Step 3 as input.
The Scanner+Renderer framework can be reused with any input scanner
definition file to scan memory images. The memory images should be
of the application which created the scanner definition file.

Later, you will need to be sure that you have compiled the
right version of the code for the step you are working on.

Once these programs have been built, the system is 
run via three bash scripts (run_slice.sh, run_build.sh, run_scan.sh)
and some manual effort.



## Running the system:

### Step 1: Collecting a Dynamic Execution Trace:

The first step of DSCRETE is to collect a dynamic slice of the
binary under investigation. This is done via the run_slice.sh
script. First, modify this script to set "PIN_DIR" to point
to your installation of Pin, "SLICING_DIR" to point to the 
parent of the pin_slicer directory, and add the binary you
want to slice to the Pin command's argument.

Executing your customized run_slice.sh should start the
libforensixslicing.so Pin tool collecting a dynamic 
execution trace.

### Some notes about slicing:

Models:
The accuracy of the slicer depends heavily on its ability to
model external library functions invoked by the binary under
investigation. The slicer will build these models automatically
using the dynamic_model_maker_mp.py python script (under
the model_maker directory in pin_slicer). This script parses
the known header files on the host system to build models of
functions from shared libraries. *For the most accurate
results you MUST download the public header files for
any library which the binary under investigation relies on.*

An unmodeled function will cause faulty dependence tracking.
Often, this will lead to a slice missing a subset of the
dependencies that the external function relies on. A function
must be modeled however to be used as a slicing criterion.

Threads:
The current slicer only traces a single thread. By default, the
tracer will follow the *child* thread/process when a new
thread/process is spawned (e.g., pthread_create or fork).
To modify this, a "-ff <file>" flag can be given to the
libforensixslicing.so Pin tool. This file is a sequence of "1"
or "0" separated by spaces. libforensixslicing.so will read
the next character in this file every time a new thread/process
is spawned, and if that character is a "1" then it will follow
the child, otherwise it will continue tracing the parent.
If EOF is reached, then libforensixslicing.so will continue
to do whatever the last character was (i.e, if the last character
is "0" then it will continue to follow the parent for all
future new thread/process spawns). Note that this file
*must* begin with a "1" because libforensixslicing.so
checks this file when the main thread is initially spawned.

Output Functions:
To cut down on the number of functions marked as "output
functions" in DSCRETE, you should define an output.symbols
file in the current working directory. This file tells DSCRETE
which function you suspect will produce application output
(i.e., the F functions from the DSCRETE paper). The format of
this file is as follows: a function name (e.g., fwrite), the
"@" sign, and the library name holding that function (e.g.,
libc.so). An example of this file would look like:

~~~~
write@libc.so
fwrite@libc.so
_IO_fwrite@libc.so
~~~~

This instructs DSCRETE to treat these as output functions,
one of which is the F function we wish to find.



## Step 2: Computing a Backwards Slice:

After you finish executing the binary under investigation
with the dynamic slicer, several output files will be put into
an "output" directory in the current working directory. 

run_slice.sh will then present you with a Vim window showing 
two files: one is a listing of external
function invocations and the values of those function's arguments
(the __write.out file), and the other is empty (the bcrit file).

The listing of external functions will look similar to this example:

~~~~
=================================================
Routine: extern size_t fwrite (__const void *__restrict __ptr, size_t __size,
 size_t __n, FILE *__restrict __s) | Img: libc.so
Info File: heap_dumps/heap1.info | Dump File: heap_dumps/heap1.dump
RET 0x210
ARG 1 0x7f33aee0832f 1 REG_DEP 13 (rsi) 0x000000001 [........]
ARG 2 0x7f33aee08327 1 REG_DEP 17 (rdx) 0x000000210 [........]
ARG 0 0x7f33aee08334 1 REG_DEP 12 (rdi) 0x000734520 [ Es.....]
0x800000000 37890 MEM_DEP 0x000734520 0x464a1000e0ffd8ff [......JF]
0x800000000 37890 MEM_DEP 0x000734528 0x4800010101004649 [IF.....H]
~~~~


Copy the lines of this file which show the forensically interesting data
you wish to slice upon into the empty bcrit file in Vim, and save the
file. If a line you wish to copy begins with "ARG #" do not copy
the "ARG #".

For the example above, we may only copy:
~~~~
0x7f33aee08334 1 REG_DEP 12 (rdi) 0x000734520 [ Es.....]
0x800000000 37890 MEM_DEP 0x000734520 0x464a1000e0ffd8ff [......JF]
~~~~

Save the bcrit file (that you copied the lines into) and close Vim.
Note that sometimes DSCRETE's closure point candidate identification
accuracy can be improved by excluding lines that start with
0x800000000.

run_slice.sh will now use the copied lines (saved into the bcrit file)
as input to the analysis program to perform slice computation.

Also note the Info File, Dump File, Routine name, and Img name
mentioned in the __write.out file. We will use these later to
test entry point candidates.



## Step 3: Building a Scanner+Renderer tool:

Note: Be sure you have libforensixscanner.so compiled
with BUILD_SCANNER defined!

To build a Scanner+Renderer tool you first must modify the 
run_build.sh script. The following variables should be changed:

PIN_DIR = like before, your pin installation

SCANNER_DIR = like before, the parent directory of the
  pin_scanner directory
  
MEM_INFO = The Info file from Step 2

MEM_DUMP = The Dump file from Step 2

PERCENT = The amount of the slice to consider (this is the
  "p" percent from the DSCRETE paper).
  
You will also need to add the binary you are inspecting
to the Pin command line at the bottom of the script.
Note that the script will not execute this command,
but just build the parameters and print the final
command for you to run.

Note that the input to this invocation of the inspected
binary should be different than used previously. You
want the data in the lines you copied into the bcrit
file to be *obviously different*.

Before running run_build.sh, you should mark the sections of
the Info File from Step 2 which DSCRETE should use for testing.
The Info File will contain lines similar to this:
~~~~
[heap]    cd0000->10162176->563000
~~~~

To mark this section for scanning, add "^scan^" to the front
of the line in the Info File, such as:
~~~~
^scan^[heap]    cd0000->10162176->563000
~~~~

Running run_build.sh will first parse the output from Step 2
and locate which function/argument you chose for the bcrit
file's values. After this parsing, run_build.sh will again open
vim and you will need to mark which argument to the
function (Routine from step 2) you chose for the bcrit file.

As the script will tell you, this should be in the format:
"#s" OR "#r" OR "#a#". In this, each "#" should be replaced
with the number of some argument to the function (likely the
"ARG #" from Step 2). Note that args start at 0!

"#s" means that you copied the buffer for argument "#" into
the bcrit file and its length in memory can be determined
via strlen. "#r" means that you copied the buffer for
argument "#" into the bcrit file and its length in memory
man be determined via the return value of the function.
"#a#" means that you copied the buffer for argument "#" into 
the bcrit file and its length in memory can be determined 
via the value of arg number "#" (the second "#").

### Recall the example __write.out file from Step 2:
~~~~
=================================================
Routine: extern size_t fwrite (__const void *__restrict __ptr, size_t __size,
 size_t __n, FILE *__restrict __s) | Img: libc.so
Info File: heap_dumps/heap1.info | Dump File: heap_dumps/heap1.dump
RET 0x210
ARG 1 0x7f33aee0832f 1 REG_DEP 13 (rsi) 0x000000001 [........]
ARG 2 0x7f33aee08327 1 REG_DEP 17 (rdx) 0x000000210 [........]
ARG 0 0x7f33aee08334 1 REG_DEP 12 (rdi) 0x000734520 [ Es.....]
0x800000000 37890 MEM_DEP 0x000734520 0x464a1000e0ffd8ff [......JF]
0x800000000 37890 MEM_DEP 0x000734528 0x4800010101004649 [IF.....H]
~~~~


We can see that the buffer is pointed to by ARG 0 and the length of
this buffer is given in ARG 2. Thus run_build.sh will present the
following file for you to modify:

~~~~
0x8a337 /lib/libc.so
Hint: Arg 0 matches! Suggest: "0s" OR "0r" OR "0a#?" #? is the number of the length arg (Args start at 0!).
fwrite
~~~~

We can see from the "Hint" line that DSCRETE matched ARG 0 to the
buffer you copied to the bcrit file, but DSCRETE cannot determine
which argument gives its length. Since we can see from the
__write.out file that ARG 2 gives the buffer's length, we change
the "Hint" line to "0a2" meaning "the buffer is pointed to
by ARG 0 and its length is in ARG 2." The saved file should 
look like this:

~~~~
0x8a337 lib/libc.so
0a2
fwrite
~~~~

Saving this file will resume run_build.sh.

After you have marked the function and argument you copied in
Step 2, run_build.sh will verify that it has all of the 
information to begin generating a Scanner+Renderer tool.
If all requirements are met, run_build.sh will print a 
lengthy command for you to invoke which will run Pin 
with libforensixscanner and several options followed by
the command you added for the inspected binary.

Running this command may lead to a segfault as soon as
the process starts. In this case, the problem is likely
the Info File. By default, DSCRETE tries to identify
which segments are heap/stack and should
be mapped back into memory, but this often fails. Please help
DSCRETE out by adding a "!" to the front of each line which it
may not need to map back into memory. For example:
We probably do not need to remap the VDSO. So the line:
~~~~
[vdso] 7fff621ff000->4096->4a37b000
~~~~
should be changed to:
~~~~
![vdso] 7fff621ff000->4096->4a37b000
~~~~

Keep rerunning the Pin command and if it segfaults again, then
add "!" to more lines. Iterate this process until
you see "Testing <number> Possible Closures ..." on
the terminal.

Once the Pin tools starts the application, you will need
to drive the execution to the same path you executed in
the first run. During this process, DSCRETE will be testing
closure point candidates in the background. Note that the
app may crash during this process. DSCRETE will mark how
many candidates it had tested before the crash. You should
rerun the Pin command (re-executing the binary). You should
notice that the number of candidates to test has reduced. 
Keep repeating this until all candidate closure points have
been executed. You can check which candidates have been
executed by looking at the scanner_info directory created
in your current working directory. NOTE: You must save the
__matches.out file and scanner_info directory between
each execution! They will be overwritten!

You can check the __matches.out file to see the output of
each closure point candidate. This file will contain
textual output produced by each candidate. This file will
contain entries such as:

~~~~
20===== Scanning from de7c20:
1 0 obj
<<
/Type /Page
/Parent 4 0 R
/Resources 11 0 R
/MediaBox [ 0 0 612 792 ]
~~~~

It is often useful for this data to be written to separate files
for each candidate (e.g., when testing JPG data it would
be useful to have 1 JPG file written per candidate rather than
the __matches.out file being filled with raw JPG data). 
To enable this, you can uncomment the FILE_OUTPUT macro
in pin_scanner/pin_scan.cpp. This will cause the output
of each candidate to be directed to a file in the 
scan_output_files directory. In this case, the __matches.out
file will look like this:

~~~~
9===== Scanning from e19bc0:
./scan_output_files/s_19_0xe19bc0.data
~~~~

You should (as the DSCRETE paper says) find the candidates which
result in the same output you marked in Step 2. When such a
candidate is found, note the candidate number before the
"===== Scanning..." in the __matches.out file. You should
find a scanner#.info file under the scanner_info directory.
This scanner#.info file is the key information needed for the
Scanner+Renderer tool.



## Step 4: Memory Image Scanning:

Note: Be sure you have libforensixscanner.so compiled
with BUILD_SCANNER **NOT** defined!

The memory dumps that DSCRETE scans must be in the format
defined in pin_scanner/pin_scan.cpp. To dump an individual
process's memory, I have included the dump_process_memory.sh 
script. This outputs a memory image for a process that DSCRETE
can scan. If you are using a different tool to dump memory,
then you just have to convert the file format into what DSCRETE
is expecting.

Again, you must mark each segment in the memory info file
that you wish to scan with "^scan^". Also, you may (again) 
need to exclude a few segments to prevent the scanner from
crashing.

You must modify the run_scan.sh script, like before, to set
MEM_INFO and MEM_DUMP to the memory image you wish to scan,
and set SCANNER_INFO to the scanner info file you chose as
the correct candidate. To speed up the scan, you may set
THREADS to some high number to allow for more parallelism.
Lastly, you should add your binary's command to the Pin
command at the bottom of the script.

You may want to save __matches.out and the scan_output_files
directory because the scan will overwrite them.

Now execute run_scan.sh to start the binary and begin the
scan. You may be prompted if you want to reuse the old
./output/crit_func_list.out, and you should answer yes
to this. Like the DSCRETE paper says, you will have to
execute the binary to the point where scanning begins. At
that point DSCRETE will take over and perform the memory
image scanning. The results of which will again be in
__matches.out and (optionally) the scan_output_files directory.


