.PHONY: install lint format type test check run-stdio run-http build

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check --fix .
	uv run ruff format .

type:
	uv run mypy

test:
	uv run pytest --cov

check: lint type test

run-stdio:
	uv run python -m mcp_hub --transport stdio

run-http:
	uv run python -m mcp_hub --transport http

build:
	docker build -t mcp-hub:dev .
