# Cybersecurity Agent with Large Language Model for Automotive
This project implements cybersecurity red-team (attacker) RL + LLM agents in Microsoft’s **CyberBattleSim** environment.

Environment & RL Model base:
- CyberBattleSim: https://github.com/microsoft/CyberBattleSim

LLM Model base:
- Defenderbench: https://github.com/microsoft/DefenderBench

Additional project documentation is available in `/doc`.

## 1. Problem Statement

## 2. Model Overview

### 2.1. RL Attacker Agents
Cybersecurity red-team (attacker) RL agents in Microsoft's CyberBattleSim
- https://github.com/HoyoenKim/CyberSecurity-RL

### 2.2. LLM Attacker Agents

### 2.3. RL + LLM Hybrid Attacker Agents

## 3. Setup

### 3.1. Install
The instructions were tested on a Linux Ubuntu distribution (both native and via WSL).

If conda is not installed already, you need to install it by running the `install_conda.sh` script.

```bash
bash install-conda.sh
```

Once this is done, open a new terminal and run the initialization script:
```bash
bash init.sh
```
This will create a conda environmen named `cybersimllm` with all the required OS and python dependencies.

To activate the environment run:

```bash
conda activate cybersimllm
```

### 3.2. Troubleshooting

#### 3.2.1. Missing `jupytext` / `papermill`

If you see:

```bash
jupytext: command not found
papermill: command not found
```

Install both packages via conda-forge:

```bash
conda install -c conda-forge jupytext papermill -y
```

#### 3.2.2. Missing `Jupyter kernel (python3)`

If you see:

```bash
jupyter_client.kernelspec.NoSuchKernel: No such kernel named python3
```

Install the Jupyter kernel dependencies and register the kernel:

```bash
conda install -c conda-forge -y ipykernel jupyter jupyter_client
python -m ipykernel install --user --name python3 --display-name "Python 3 (cybersimllm)"
```

#### 3.2.3. Inompatible `plotly` and `kaleido`

If you see:

```bash
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts. cyberbattlesim 0.1.0 requires plotly~=5.15.0, but you have plotly 6.5.0 which is incompatible.
```

Reinstall the plotly and kaleido

```bash
python -m pip uninstall -y plotly kaleido
python -m pip install -U "plotly==5.15.0" "kaleido==0.2.1"
```

#### 3.2.4. Missing `torch`

If you see:

```bash
ModuleNotFoundError: No module named 'torch'
```

Install the torch 

```bash
pip install torch
```

## 4. Run & Results

### 4.1. Pre-result of RL Agent

cyberbattlesim chain, toyctf RL model reuslts are here
- https://github.com/HoyoenKim/CyberSecurity-RL

#### CyberBattleSim-Chain
| Agent | Nodes Found | Nodes Exploited |
|---:|:---:|:---:|
| Random | 3 / 11 | 2 / 11 |
| Rule-Based | 5 / 11 | 5 / 11 |
| Tabular Q-Learning | 5 / 11 | 5 / 11 |
| Deep Q-Learning (DQN) | 11 / 11 | 11 / 11 |
| Deep Recurrent Q-Learning (DRQN) | 11 / 11 | 11 / 11 |

#### CyberBattleSim-CTF
| Agent | Nodes Found | Nodes Exploited |
|---:|:---:|:---:|
| Answer (Oracle) | 9 / 9 | 5 / 5 |
| Random | 3 / 9 | 1 / 5 |
| Rule-Based | 5 / 9 | 1 / 5 |
| Tabular Q-Learning | 5 / 9 | 1 / 5 |
| Deep Q-Learning (DQN) | 9 / 9 | 5 / 5 |
| Deep Recurrent Q-Learning (DRQN) | 9 / 9 | 5 / 5 |

### 4.2. Pre-result of LLM Agent

cyberbattlesim chain, toyctf LLM model results are here
- https://github.com/microsoft/DefenderBench

| Model | CyberBattleSim-Chain | CyberBattleSim-CTF | 
| --- | --- | --- |
|     | winning % | winning % |
| Llama 3.1 8B | 23.61 | 16.67 |
| Llama 3.1 70B | 77.78 | **44.44** |
| Llama 3.3 70B | **100.00** | 33.33 |


### 4.3. Automotive Environment

```bash
./src/notebooks/run_automotive_ctf_solved.sh python3
```

![automotive_ctf_solved](figures/automotive_ctf_solved.gif)

### 4.4. Base RL Agent

#### 4.4.1. Rule-Based
```bash
./src/notebooks/run_automotive_ctf_rulebased.sh python3
```

![automotive_ctf_rulebased](figures/automotive_ctf_rulebased.gif)

#### 4.4.2. Deep Q-Learning

```bash
./src/notebooks/run_automotive_ctf_dql.sh python3
```

![automotive_ctf_dql](figures/automotive_ctf_dql.gif)

### 4.5. Native LLM Agent

### 4.6. RL + LLM Hybrid Agent

## 5. Discussion
