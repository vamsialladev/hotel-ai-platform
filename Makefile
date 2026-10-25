.PHONY: check test lint redteam sbom
check: lint test redteam
lint:
	ruff check .
	ruff format --check .
test:
	python -m pytest --cov --cov-fail-under=85
redteam:
	python -m hotelplatform.redteam --min-pass 1.0
sbom:
	cyclonedx-py environment --output-format JSON --output-file sbom.json
