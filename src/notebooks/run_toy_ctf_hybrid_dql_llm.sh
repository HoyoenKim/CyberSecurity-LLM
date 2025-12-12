#!/bin/bash
set -ex

kernel=$1
if [ -z "$kernel" ]; then
    kernel=cybersim
fi

script_dir=$(dirname "$0")

pushd "$script_dir/.."

output_dir=notebooks/output/toyctf_hybrid_dql_llm
output_plot_dir=$output_dir/plots

run () {
    base=$1
    suffix=$2
    cat notebooks/$base.py \
        | jupytext --to ipynb  - \
        | papermill --kernel $kernel $output_dir/$base$suffix.ipynb  "${@:3}"
}

jupyter kernelspec list

mkdir $output_dir -p
mkdir $output_plot_dir -p

run toy_ctf_hybrid_dql_llm '-toy-ctf-llm' -y "
    gymid: 'CyberBattleToyCtf-v0'
    env_size: null
    iteration_count: 500
    training_episode_count: 20
    eval_episode_count: 10
    maximum_node_count: 12
    maximum_total_credentials: 10
    plots_dir: $output_plot_dir

    use_llm: true
    model_id: 'gpt-5.1'
    llm_every_steps: 5
    candidate_pool: 200
    llm_topk: 10
"