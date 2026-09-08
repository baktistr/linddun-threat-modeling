#!/usr/bin/env bash
# Drive run_open_model_sweep.py across the ladder, restarting the vLLM container per model.
#
# The model is an outer loop OUTSIDE the Python because a local server holds exactly one model:
# switching means restarting the container, which is orchestration, not experiment logic. Keeping
# it here leaves the Python script honest -- it runs against whatever is served and asserts the
# id matches, rather than pretending it can switch models itself.
#
# Resumable at two levels: this loop is idempotent, and the Python skips cells already in STATE.
# An interrupted sweep is re-invoked with the same command.
#
# Usage: scripts/run_open_model_sweep.sh [model ...]
set -uo pipefail

REPO="${REPO:-/root/linddun}"
HF_DIR="${HF_DIR:-/mnt/data/hf}"
IMAGE="${IMAGE:-vllm/vllm-openai:latest}"
RUNS="${RUNS:-3}"
CONCURRENCY="${CONCURRENCY:-16}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-16384}"
# Pinned, not left to vLLM's default. Qwen3.5's Gated DeltaNet layers need one Mamba cache
# block per sequence, and on a 96GB card the 27B leaves room for 609 against a default
# max_num_seqs of 1024 -- CUDA graph capture then refuses to start and the model never serves.
# It also removes an unrecorded variable: CUDA graph capture sizes are part of the batching
# behaviour that makes greedy decoding non-deterministic here, so the value belongs in the
# run record rather than in whatever the default happened to be on that GPU.
MAX_NUM_SEQS="${MAX_NUM_SEQS:-256}"
GPU_UTIL="${GPU_UTIL:-0.90}"
MODELS=("${@:-Qwen/Qwen3.5-2B}")

serve() {                                    # $1 = model id
  docker rm -f vllm >/dev/null 2>&1
  docker run -d --name vllm --gpus all -p 8000:8000 --ipc=host \
    -v "$HF_DIR:/root/.cache/huggingface" \
    "$IMAGE" --model "$1" \
    --max-model-len "$MAX_MODEL_LEN" --gpu-memory-utilization "$GPU_UTIL" \
    --max-num-seqs "$MAX_NUM_SEQS" \
    --reasoning-parser qwen3 --enable-auto-tool-choice --tool-call-parser qwen3_coder \
    >/dev/null || return 1
  # Wait for readiness rather than sleeping a guessed interval: a 27B takes ~4.5 min to load and
  # a 2B under one, and starting the sweep against a server still loading fails every cell.
  for _ in $(seq 1 90); do
    curl -sf localhost:8000/v1/models >/dev/null 2>&1 && return 0
    docker ps --filter name=vllm --format '{{.Names}}' | grep -q vllm || return 1
    sleep 10
  done
  return 1
}

for MODEL in "${MODELS[@]}"; do
  echo "=== $(date +%H:%M:%S) serving $MODEL ==="
  if ! serve "$MODEL"; then
    echo "!!! $MODEL failed to come up -- skipping. Last logs:"
    docker logs vllm 2>&1 | tail -30
    continue
  fi
  echo "=== $(date +%H:%M:%S) sweeping $MODEL ==="
  ( cd "$REPO" && PYTHONPATH=. GENERATION_CONCURRENCY="$CONCURRENCY" \
      .venv/bin/python scripts/run_open_model_sweep.py \
        --model "$MODEL" --runs "$RUNS" --concurrency "$CONCURRENCY" )
  echo "=== $(date +%H:%M:%S) done $MODEL ==="
done

echo "=== SWEEP COMPLETE ==="
