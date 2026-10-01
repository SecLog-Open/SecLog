FROM docker.pengyihao.top/library/python:3.12.4-bookworm

COPY ./poetry-install.py /
RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --default-timeout=300 poetry

ENV PATH="$PATH:/root/.local/bin"
WORKDIR /app
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PIP_DEFAULT_TIMEOUT=300
ENV POETRY_HTTP_TIMEOUT=600
ENV POETRY_REQUESTS_TIMEOUT=600
ENV POETRY_INSTALLER_MAX_WORKERS=1
ENV POETRY_VIRTUALENVS_CREATE=false

COPY pyproject.toml poetry.lock /app/
RUN poetry install --no-interaction --no-ansi --no-root

COPY . /app

CMD ["sleep", "infinity"]
