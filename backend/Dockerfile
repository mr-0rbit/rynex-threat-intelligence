FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy the package before installing so the wheel is not empty. Installing the
# project (rather than only its dependencies) keeps the installed metadata and
# console entry points consistent with what CI tests.
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir . && pip check

COPY alembic ./alembic
COPY alembic.ini ./

RUN useradd -m rtip && chown -R rtip:rtip /app
USER rtip

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
