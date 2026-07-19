param(
    [string]$Python = ".\.venv\Scripts\python.exe"
)

& $Python -m pytest --cov=logiclab --cov-report=term-missing
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Python -m ruff check src tests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Python -m alembic check
exit $LASTEXITCODE
