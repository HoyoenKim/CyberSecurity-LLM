#!/bin/bash
set -ex

kernel=$1
if [ -z "$kernel" ]; then
    kernel=cybersim
fi

script_dir=$(dirname "$0")

pushd "$script_dir/.."

output_dir=notebooks/output/automotive_ctf_rulebased
output_plot_dir=$output_dir/plots

run () {
    base=$1
    suffix=$2
    cat notebook notebooks/$base.py \
        | jupytext --to ipynb  - \
        | papermill --kernel $kernel $output_dir/$base$suffix.ipynb  "${@:3}"
}

jupyter kernelspec list

mkdir $output_dir -p
mkdir $output_plot_dir -p

run automotive_ctf_rulebased '-automotive_ctf' -y "
    gymid: 'CyberBattleAutomotiveCTF-v0'
    env_size: null
    iteration_count: 100
    training_episode_count: 20
    eval_episode_count: 10
    maximum_node_count: 32
    maximum_total_credentials: 10
    plots_dir: $output_plot_dir
"