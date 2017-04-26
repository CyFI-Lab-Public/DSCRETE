#!/bin/bash

rm -rf dynamic_modeler.log dynamic_modeler_err.log

exec >  >(tee -a dynamic_modeler.log)
exec 2> >(tee -a dynamic_modeler_err.log >&2)

${DYN_MODEL_MAKER_PATH}/dynamic_model_maker_mp.py
