#!/bin/bash

set -ex

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

pushd "$(dirname "$0")"

conda info --envs

eval "$(conda shell.bash hook)"

if conda info --envs | grep -q cybersimllm; then
  echo "env already exists";
else
  conda env create -f env.yml;
fi

conda activate cybersimllm

python --version

if [ ""$GITHUB_ACTION"" == "" ] && [ -d ".git" ]; then
  echo 'running under a git enlistment -> configure pre-commit checks on every `git push` to run pyright and co'
  pre-commit install -t pre-push
fi

./createstubs.sh

popd
