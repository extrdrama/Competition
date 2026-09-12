# 演示样本：镜像构建 ENV 残留是镜像渠道的核心命中点
FROM python:3.12-slim

ARG PIP_INDEX_URL=https://pypi.org/simple
ENV APP_HOME=/opt/api
ENV SECRET_KEY=Kr9vmu7yL1GbrKOC2d3mkVBeIj9Ug09fDaBJAjxh
ENV ACCESS_TOKEN=mjuKnCl5PSuENtKmCmWSYt909REVpWcr
ENV DB_PASSWORD=Pr0d_xJYLv619qcS6

WORKDIR $APP_HOME
COPY . $APP_HOME
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "-m", "api"]
