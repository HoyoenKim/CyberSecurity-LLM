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

To using llm model, save huggingface token at llm_token.yaml like this.

```yaml
huggingface:
  api_token: "hf_token"
openai:
  api_token: "api_key"
```

Test llm is available.

```bash
python3 ./src/notebooks/test_huggingface.py
python3 ./src/notebooks/test_openai.py
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

#### 4.5.1. llama 3.1 8B

#### 1) CyberBattleSim-Chain10

```bash
python3 ./src/notebooks/run_huggingface_llm.py \
    --env chain10 \
    --model_id meta-llama/Llama-3.1-8B-Instruct \
    --max_steps 100 \
    --output_dir ./src/notebooks/output/chain10_llama31_8B > ./src/notebooks/output/chain10_llama31_8B/chain10_Llama-3.1-8B-Instruct_log.txt
```

```text
Thought: I should try to use ScanExplorerRecentFiles on 2_WindowsNode to see if I can find any new information.
Thought: Since ScanExplorerRecentFiles is not supported on Windows, I should try a different vulnerability.
Thought: I can try to use SudoAttempt on 2_WindowsNode to see if I can get a credential for 3_LinuxNode.
Thought: However, I should be careful because I've already tried to use SudoAttempt and it didn't work.
Thought: I should try to use CrackKeepPassX on 2_WindowsNode to get a credential for 3_LinuxNode.
Thought: However, I've already tried using CrackKeepPassX on 2_WindowsNode before and it didn't work.
Thought: I can try to use RDP on 2_WindowsNode to get a credential for 3_LinuxNode.
Thought: I can try to connect to 3_LinuxNode using the credential for 2_WindowsNode.
Thought: I can try to use CrackKeepPass on 2_WindowsNode to get a credential for 3_LinuxNode.
Thought: However, I've already tried using CrackKeepPass on 1_LinuxNode before and it didn't work.
Thought: I should try a different vulnerability that might give me a credential for 3_LinuxNode.
Thought: I can try to use ScanBashHistory on 2_WindowsNode to see if I can find any new information.
Thought: However, I should be careful because I've already tried to use ScanBashHistory on 2_WindowsNode and it didn't work.
Thought: I should try a different vulnerability that might give me a credential for 3_LinuxNode.
Thought: Since 2_WindowsNode is connected to 3_LinuxNode, I can try to use CrackKeepPassX on 2_WindowsNode.
Thought: However, CrackKeepPassX is not supported on Windows.
Thought: I should try a different vulnerability that might give me a credential for 3_LinuxNode.
Thought: I've already tried multiple vulnerabilities on 2_WindowsNode, but none of them worked.
Thought: I should try to use the credential for 2_WindowsNode to connect to 3_LinuxNode.
Thought: I can try to connect to 3_LinuxNode using the credential for 2_WindowsNode.
Thought: However, I need a credential for 3_LinuxNode to connect to it.
```

```bash
Final Score: 4/12
```

logs are available at 
- [llama3.1. 7B Chain10 Logs](./src/notebooks/output/chain10_llama31_8B/chain10_Llama-3.1-8B-Instruct_log.txt)

#### 2) CyberBattleSim-CTF

```bash
python3 ./src/notebooks/run_huggingface_llm.py \
    --env toyctf \
    --model_id meta-llama/Llama-3.1-8B-Instruct \
    --max_steps 100 \
    --output_dir ./src/notebooks/output/toyctf_llama31_8B > ./src/notebooks/output/toyctf_llama31_8B/toyctf_Llama-3.1-8B-Instruct_log.txt
```

```bash
Final Score: 1/6
```

src\notebooks\output\chain10_llama31_8B\chain10_Llama-3.1-8B-Instruct_log.txt
logs are available at 
- [llama3.1. 7B ToyCTF Logs](./src/notebooks/output/toyctf_llama31_8B/toyctf_Llama-3.1-8B-Instruct_log.txt)

#### 3) CyberBattleSim-Automotive

```bash
python3 ./src/notebooks/run_huggingface_llm.py \
    --env automotive \
    --model_id meta-llama/Llama-3.1-8B-Instruct \
    --max_steps 100 \
    --output_dir ./src/notebooks/output/automotive_ctf_llama31_8B > ./src/notebooks/output/automotive_ctf_llama31_8B/automotive_ctf_Llama-3.1-8B-Instruct_log.txt
```

``` Text
Thought: We've tried many remote vulnerability attacks on the OBD node that are supported by the AttackerLaptop node, but none of them are supported by the AttackerLaptop node.
Thought: We should try to perform a different type of attack.
Thought: We can try to perform a "connect" action to establish a connection between the AttackerLaptop node and another node in the network.
Thought: However, we've already tried to connect to the OBD node via USB and it was blocked.
Thought: We should try to connect to another node in the network that might be more vulnerable.
Thought: We can try to connect to the AttackerLaptop node itself, but we already own it.
Thought: We should try to connect to a different node in the network.
Thought: Let's try to connect to a node that we haven't tried to connect to yet.
Thought: We don't have any information about other nodes in the network, so we can't choose a specific node to connect to.
Thought: We should try to perform a different type of attack.
Thought: We can try to perform a local vulnerability attack on the AttackerLaptop node to discover more nodes or credentials.
Thought: We have already tried many local attacks on the AttackerLaptop node, but none of them are supported by the AttackerLaptop node.
Thought: We should try to perform a different local attack that might give us more information about the network.
Thought: One option is to perform a "DumpIMUOffsets" attack on the AttackerLaptop node. However, this attack is not supported by the AttackerLaptop node.
Thought: Another option is to perform a "DumpTestLogs" attack on the AttackerLaptop node. However, this attack is not supported by the AttackerLaptop node.
Thought: We should try to perform a "DumpGatewayAdminToken" attack on the AttackerLaptop node. However, this attack is not supported by the AttackerLaptop node.
Thought: We can try to perform a "DumpVCUState" attack on the AttackerLaptop node. However, this attack is not supported by the AttackerLaptop node.
Thought: We should try to perform a "DumpVehicleBackendConfig" attack on the AttackerLaptop node. However, this attack is not supported by the AttackerLaptop node.
```

```bash
Final Score: 2/6
```

logs are available at 
- [llama3.1. 7B AutomotiveCTF Logs](./src/notebooks/output/automotive_ctf_llama31_8B/automotive_ctf_Llama-3.1-8B-Instruct_log.txt)
#### 4.5.2. chatgpt 5.1

#### 1) CyberBattleSim-Chain10

```bash
python3 ./src/notebooks/run_openai_llm.py \
    --env chain10 \
    --model_id gpt-5.1 \
    --max_steps 100 \
    --output_dir ./src/notebooks/output/chain10_chatgpt51 > ./src/notebooks/output/chain10_chatgpt51/chain10_chatgpt51.txt
```

```bash
Final Score: 12/12
```

logs are available at 
- [GPT 5.1. Chain10 Logs](./src/notebooks/output/chain10_chatgpt51/chain10_chatgpt51.txt)

#### 2) CyberBattleSim-CTF
```bash
python3 ./src/notebooks/run_openai_llm.py \
    --env toyctf \
    --model_id gpt-5.1 \
    --max_steps 100 \
    --output_dir ./src/notebooks/output/toyctf_chatgpt51 > ./src/notebooks/output/toyctf_chatgpt51/toyctf_chatgpt51.txt
```

```bash
Final Score: 3/6
```

logs are available at 
- [GPT 5.1. ToyCTF Logs](./src/notebooks/output/toyctf_chatgpt51/toyctf_chatgpt51.txt)

#### 3) CyberBattleSim-Automotive

```bash
python3 ./src/notebooks/run_openai_llm.py \
    --env automotive \
    --model_id gpt-5.1 \
    --max_steps 100 \
    --output_dir ./src/notebooks/output/automotive_ctf_chatgpt51 > ./src/notebooks/output/automotive_ctf_chatgpt51/automotive_ctf_chatgpt51.txt
```

logs are available at 
- [GPT 5.1. AutomotiveCTF Logs](./src/notebooks/output/automotive_ctf_chatgpt51/automotive_ctf_chatgpt51.txt)

```bash
Final Score: 6/6
```

#### 4.5.2. chatgpt 5.2

#### 1) CyberBattleSim-CTF

```bash
python3 ./src/notebooks/run_openai_llm2.py \
    --env toyctf \
    --model_id gpt-5.2 \
    --max_steps 200 \
    --output_dir ./src/notebooks/output/toyctf_chatgpt52 > ./src/notebooks/output/toyctf_chatgpt52/toyctf_chatgpt52.txt
```

```bash
Final Score: 3/6
```

logs are available at 
- [GPT 5.2. ToyCTF Logs](./src/notebooks/output/toyctf_chatgpt52/toyctf_chatgpt52.txt)

#### 4.5.3. LLM Agent auto report generate

#### 1) CyberBattleSim-Chain

```bash
python3 ./src/notebooks/run_llm_report.py \
  --input_json ./src/notebooks/output/chain10_chatgpt51/chain10_gpt-5.1.json \
  --env chain10 \
  --model gpt-5.1 \
  --output_md ./src/notebooks/output/chain10_chatgpt51/chain10_gpt-5.1.md
```

reports are available at 
- [Chain10 Security Report](./src/notebooks/output/chain10_chatgpt51/chain10_gpt-5.1.md)

#### 2) CyberBattleSim-CTF

```bash
python3 ./src/notebooks/run_llm_report.py \
  --input_json ./src/notebooks/output/toyctf_chatgpt51/toyctf_gpt-5.1.json \
  --env toyctf \
  --model gpt-5.1 \
  --output_md ./src/notebooks/output/toyctf_chatgpt51/toyctf_gpt-5.1.md
```

reports are available at 
- [ToyCTF Security Report](./src/notebooks/output/toyctf_chatgpt51/toyctf_gpt-5.1.md)

#### 3) CyberBattleSim-Automotive

```bash
python3 ./src/notebooks/run_llm_report.py \
  --input_json ./src/notebooks/output/automotive_ctf_chatgpt51/automotive_ctf_gpt-5.1.json \
  --env automotive \
  --model gpt-5.1 \
  --output_md ./src/notebooks/output/automotive_ctf_chatgpt51/automotive_ctf_gpt-5.1.md
```

reports are available at 
- [Automotive CTF Security Report](./src/notebooks/output/automotive_ctf_chatgpt51/automotive_ctf_gpt-5.1.md)

#### 4.5.4. Troubleshooting

#### 1) If you got `our prompt was flagged as potentially violating our usage policy`


```bash
openai.BadRequestError: Error code: 400 - {'error': {'message': 'Invalid prompt: your prompt was flagged as potentially violating our usage policy. Please try again with a different prompt: https://platform.openai.com/docs/guides/reasoning#advice-on-prompting', 'type': 'invalid_request_error', 'param': None, 'code': 'invalid_prompt'}}
```

fix prompt

### 4.6. RL + LLM Hybrid Agent

deep rl -> good at toy ctf (복잡)
llm -> good at automotive ctf (생소)

hybrid model -> good at both


RL: DQL
LLM: chatgpt 5.1.


#### 1) Toy CTF

```bash
./src/notebooks/run_chain10_hybrid_dql_llm.sh python3
```

#### 2) Toy CTF

```bash
./src/notebooks/run_toy_ctf_hybrid_dql_llm.sh python3
```

#### 3) Automotive CTF

```bash
./src/notebooks/run_automotive_ctf_hybrid_dql_llm.sh python3
```

## 5. Discussion