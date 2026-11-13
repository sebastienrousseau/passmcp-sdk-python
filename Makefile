# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

export PYTHONDONTWRITEBYTECODE := 1

PYTHON ?= python3
PYTEST ?= pytest
RUFF ?= ruff
REUSE ?= reuse

.PHONY: check test lint reuse family lockstep example

check: lint reuse test example

test:
	PYTHONPATH=src $(PYTEST) -q -p no:cacheprovider

lint:
	$(RUFF) check src tests examples

reuse:
	$(REUSE) lint

family:
	./scripts/family.sh

lockstep:
	./scripts/lockstep.sh

example:
	PYTHONPATH=src $(PYTHON) examples/quickstart.py
