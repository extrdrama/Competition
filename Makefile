# 凭迹 CredWatch —— 常用命令
# Python 解释器可通过 PY 变量覆盖，例如：
#   make demo PY=/usr/bin/python3

PY ?= python
OUT ?= output

.PHONY: help install demo test lint scan-local scan-all watch serve report \
        docs samples clean docker-build docker-up docker-down

help:
	@echo "凭迹 CredWatch —— 可用命令"
	@echo ""
	@echo "  make install        安装运行依赖"
	@echo "  make init           初始化数据库并检查配置"
	@echo "  make demo           离线演示（三渠道，无需联网与令牌）"
	@echo "  make test           运行全部单元测试"
	@echo "  make samples        重新生成演示语料（伪造凭据）"
	@echo "  make docs           从代码重新生成渠道/凭据清单文档"
	@echo "  make sources        查看渠道清单与可用性"
	@echo "  make rules          查看规则库覆盖情况"
	@echo "  make scan-local DIR=路径   扫描本地/内网目录"
	@echo "  make scan-all       扫描全部已启用在线渠道"
	@echo "  make watch          常驻扫描模式"
	@echo "  make serve          启动可视化看板"
	@echo "  make report         用数据库现有数据出报告"
	@echo "  make docker-build   构建镜像"
	@echo "  make clean          清理生成物（数据库、报告、缓存）"

install:
	$(PY) -m pip install -r requirements.txt

init:
	$(PY) -m credwatch init

demo:
	$(PY) -m credwatch demo --out $(OUT)

test:
	$(PY) -m unittest discover -s tests -t . -v

samples:
	$(PY) scripts/make_demo_samples.py

docs:
	$(PY) scripts/generate_docs.py

sources:
	$(PY) -m credwatch sources --health

rules:
	$(PY) -m credwatch rules

scan-local:
	@test -n "$(DIR)" || (echo "用法：make scan-local DIR=要扫描的目录"; exit 1)
	$(PY) -m credwatch scan-local $(DIR) --out $(OUT)

scan-all:
	$(PY) -m credwatch scan --all --out $(OUT)

watch:
	$(PY) -m credwatch watch --interval 600

serve:
	$(PY) -m credwatch serve

report:
	$(PY) -m credwatch report --out $(OUT)

docker-build:
	docker build -t credwatch:1.0.0 .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	@echo "清理生成物（保留源码与样本）…"
	rm -rf data/$(if $(wildcard data/*.db),*.db,) output/*.md output/*.json output/*.csv
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "完成。"
