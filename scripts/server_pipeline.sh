#!/bin/bash
# CredData 基准对比实验（服务器端流水线）
set -u
cd /mnt/data/zjx/competition
mkdir -p bin output logs

# 1) gitleaks 8.30.1（Linux x64）
if [ ! -x bin/gitleaks ]; then
  echo "下载 gitleaks..."
  wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz -O /tmp/gl.tgz \
    && tar xzf /tmp/gl.tgz -C bin gitleaks && chmod +x bin/gitleaks \
    && ./bin/gitleaks version
fi

{
  echo "[1] gitleaks start $(date +%T)"
  ./bin/gitleaks dir .bench/CredData/data --report-format json --report-path output/gitleaks_creddata.json --no-banner
  echo "[1] gitleaks done exit=$? $(date +%T)"

  echo "[2] detect-secrets start $(date +%T)"
  "$HOME/.local/bin/detect-secrets" scan --all-files --force-use-all-plugins .bench/CredData/data \
    > output/detect_secrets_creddata.json 2> logs/ds.err
  echo "[2] detect-secrets done exit=$? $(date +%T)"

  echo "[3] credwatch start $(date +%T)"
  python3 scripts/creddata_bench.py --tool credwatch \
    --dump-raw output/raw_credwatch.json --json output/creddata_credwatch_all.json
  echo "[3] credwatch done exit=$? $(date +%T)"

  echo "[4] gitleaks 评分 start $(date +%T)"
  python3 scripts/creddata_bench.py --tool gitleaks \
    --findings output/gitleaks_creddata.json --json output/creddata_gitleaks.json
  echo "[4] gitleaks 评分 done exit=$? $(date +%T)"

  echo "[5] detect-secrets 评分 start $(date +%T)"
  python3 scripts/creddata_bench.py --tool detect_secrets \
    --findings output/detect_secrets_creddata.json --json output/creddata_detect_secrets.json
  echo "[5] detect-secrets 评分 done exit=$? $(date +%T)"

  echo "ALL_DONE $(date +%T)"
} > logs/pipeline.log 2>&1
