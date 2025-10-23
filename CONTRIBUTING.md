Contributing
============

Thanks for considering contributing!

- Create a branch per feature/fix: git checkout -b feat/my-feature
- Run linters and tests locally before opening a PR.
- Keep changes focused and add tests for new behavior if possible.

Suggested checks:
```
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install flake8 pytest
flake8 --max-line-length=120
pytest
```
