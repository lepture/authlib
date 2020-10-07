#!/usr/bin/env sh
set -ex
echo $NODE_NAME
echo $PIPELINE_NODE
echo $RESERVE
echo "$BRANCH_NAME"

make build
make publish
