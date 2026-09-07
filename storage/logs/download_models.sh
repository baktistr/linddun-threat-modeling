#!/bin/bash
export HF_HOME=/mnt/data/hf
for M in Qwen/Qwen3.5-2B Qwen/Qwen3.5-4B Qwen/Qwen3.5-9B Qwen/Qwen3.5-27B; do
  echo "=== $(date +%H:%M:%S) downloading $M ==="
  /opt/hf/bin/hf download "$M" || echo "FAILED $M"
  echo "=== $(date +%H:%M:%S) done $M ==="
  df -h /mnt/data | tail -1
done
echo "ALL DOWNLOADS COMPLETE"
