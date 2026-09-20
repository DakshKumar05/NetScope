.PHONY: help install backend frontend dev test test-backend test-frontend build lint clean demo scan

help:
	@echo "Network Exposure Scanner"
	@echo ""
	@echo "  make install        Install backend and frontend dependencies"
	@echo "  make backend        Run the API on :8000"
	@echo "  make frontend       Run the web UI on :5173"
	@echo "  make test           Run every test suite"
	@echo "  make test-backend   Run the Python tests"
	@echo "  make test-frontend  Run the React tests"
	@echo "  make build          Production build of the frontend"
	@echo "  make demo           Bring up the Docker demo environment"
	@echo "  make scan T=1.2.3.4 Scan a target from the CLI"
	@echo "  make clean          Remove build artefacts and local databases"

install:
	cd backend && python -m venv .venv && ./.venv/Scripts/python.exe -m pip install -r requirements.txt || \
	  (cd backend && python3 -m venv .venv && ./.venv/bin/python -m pip install -r requirements.txt)
	cd frontend && npm install

backend:
	cd backend && uvicorn app.main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

test: test-backend test-frontend

test-backend:
	cd backend && python -m pytest

test-frontend:
	cd frontend && npm run test

build:
	cd frontend && npm run build

demo:
	docker compose up --build

scan:
	cd backend && python -m scanner_cli scan $(T) $(ARGS)

clean:
	rm -rf frontend/dist frontend/node_modules/.vite
	rm -f backend/*.db backend/*.db-wal backend/*.db-shm
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
