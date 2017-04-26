#!/bin/bash

PIN_DIR=../../pin-2.13
SLICING_DIR=../../dscrete
FOLLOW_CHILDREN=./follow_children.txt
PLUGIN_DIR=${SLICING_DIR}/pin_slicer
LIB_NAME=libforensixslicing.so
export DYN_MODEL_MAKER_PATH=${PLUGIN_DIR}/model_maker

# Clean up the old stuff
rm -rf ./output/at.out heap_dumps/ cfg/ output/ pin* cfg.info debug.info \
       bcrit fcrit dynamic_modeler_err.log dynamic_modeler.log

# ADD PIN COMMAND LINE HERE!!!
${PIN_DIR}/pin -separate_memory -t ${PLUGIN_DIR}/${LIB_NAME} -ff $FOLLOW_CHILDREN -- ADD COMMAND HERE

echo ""
echo "Moving Files ..."
mkdir ./output
mv ./*.out ./output/
mv pintool.log pintool.log.slice
grep IMG pintool.log.slice > ./output/at.out

echo ""
echo "Extract bcrit ..."
touch bcrit
vim -p ./output/__write.out bcrit

ANALYSIS_DIR=${SLICING_DIR}/analysis
ANALYSIS_NAME=analysis

echo ""
echo "Performing Trace Slicing ..."
${ANALYSIS_DIR}/${ANALYSIS_NAME} ./output
