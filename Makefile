.PHONY: install lint typecheck test verify run
install:
	python -m pip install -e ".[dev]"
lint:
	ruff check .
typecheck:
	mypy apps omega
test:
	pytest -q
verify: lint typecheck test
run:
	uvicorn apps.api.main:app --host 0.0.0.0 --port 8080
offline-verify:
	python tools/verify.py
