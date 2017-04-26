#!/bin/bash

PIN_DIR=../../pin-2.13
SCANNER_DIR=../../dscrete
PLUGIN_DIR=${SCANNER_DIR}/pin_scanner
LIB_NAME=libforensixscanner.so
BUILD_CRIT_SCRIPT=build_crit_func_list.py

MEM_INFO="./heap_dumps/heap1.info"
MEM_DUMP="./heap_dumps/heap1.dump"

BUILD_SCANNER="./output"

PERCENT="9"
THREADS="32"

GUESSES="./output/guesses.out"
FUNC_LIST="./output/crit_func_list.out"


#### FUNCTIONS ####
function prompt_save () {
  if [[ -e $1 ]]; then
    read -p "WARNING: Save old $1? " -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      mv $1 $1_old
      echo "SAVE"
    else
      rm -rf $1
      echo "KILL"
    fi
  else
    echo "NEXIST"
  fi
}

function prompt_reuse () {
  if [[ -e $1 ]]; then
    read -p "WARNING: Use old $1? " -n 1 -r
    if [[ $REPLY =~ ^[Nn]$ ]]; then
      rm -rf $1
      echo "KILL"
    else
      echo "USE"
    fi
  else
    echo "NEXIST"
  fi
}

function kill_if_missing () {
  if [ ! -e $1 ]; then
    echo "Missing $1"
    exit
  fi
}

#### END FUNCTIONS ####


# Clean up old stuff...
result=$(prompt_save __matches.out)
echo ""
result=$(prompt_save scan_output_files)
echo ""
result=$(prompt_save pintool.log)
echo ""

result=$(prompt_reuse $FUNC_LIST)
echo ""
if [ $result != "USE" ]; then
  echo ""
  echo "Extracting Crit Functions ..."
  ${SCANNER_DIR}/${BUILD_CRIT_SCRIPT} ./bcrit ./output/__write.out $MEM_INFO $FUNC_LIST
  if [ ! -e $FUNC_LIST ]; then
    exit
  fi
  vim $FUNC_LIST
fi

# Check for deps!
kill_if_missing $MEM_INFO
if ! grep --quiet \\^scan\\^ $MEM_INFO; then
  echo "No \"^scan^\" sections in $MEM_INFO"
  exit
fi
kill_if_missing $MEM_DUMP

if [ -z "$BUILD_SCANNER" ]; then
  BUILDING=0
else
  BUILDING=1
  kill_if_missing $BUILD_SCANNER
  result=$(prompt_save scanner_info)
  echo ""
fi

if [ ! -z "$SCANNER_INFO" ] && [ ! -e $SCANNER_INFO ]; then
  if [ $BUILDING = 1 ]; then
    echo "Both BUILD_SCANNER and SCANNER_INFO defined"
  else
    echo "Missing $SCANNER_INFO"
  fi
  exit
fi

if [ $BUILDING = 1 ]; then
  result=$(prompt_reuse $GUESSES)
  echo ""
  FLAG="-build_scanner $BUILD_SCANNER -p $PERCENT"
else
  FLAG="-scanner_info $SCANNER_INFO -j $THREADS"
fi

echo "Now run ..."
echo ""
echo "${PIN_DIR}/pin -tool_load_option deepbind -t ${PLUGIN_DIR}/${LIB_NAME} -t_func $FUNC_LIST -mem_info $MEM_INFO -mem $MEM_DUMP $FLAG  -- ADD YOUR BINARY'S COMMAND HERE!"
echo ""
