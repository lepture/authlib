#!/usr/bin/env sh
set -ex
echo $NODE_NAME
echo $PIPELINE_NODE
echo $NODE_LABELS
echo $RESERVE
echo $PWD

pip install tox

make tests
echo "end....."
