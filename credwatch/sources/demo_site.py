"""渠道脚手架示例（占位文件）。

本文件原本由 `python -m credwatch new-source demo_site` 生成，用于验证
脚手架能力。为避免污染正式渠道列表，这里保留为**不会注册渠道**的占位模块。

真实的扩展流程见 docs/支持的公开渠道列表.md：

    python -m credwatch new-source <渠道标识> --label "<中文名>"
"""

# 故意不实现 SourceAdapter，也不调用 @registry.register，
# 因此本模块不会向渠道注册表添加任何条目。
