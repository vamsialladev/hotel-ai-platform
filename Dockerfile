# Runs the tests and the red-team corpus in a clean image:
#   docker build -t hotel-ai-platform . && docker run --rm hotel-ai-platform
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
RUN pip install --no-cache-dir -e ".[postgres]" "pytest~=9.1" "streamlit~=1.66.1"
CMD ["sh", "-c", "python -m pytest -q && python -m hotelplatform.redteam"]
