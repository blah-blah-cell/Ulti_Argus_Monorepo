#!/bin/bash
cd /home/engine/project
echo "Starting NSL-KDD training at $(date)"

/usr/bin/python3 scripts/train_nsl_kdd.py 2>&1

echo "Finished at $(date)"
