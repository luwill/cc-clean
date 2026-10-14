.PHONY: check lint test

check: lint test

lint:
	python3 -B tools/check_source.py

test:
	python3 -B -m unittest discover -s . -p 'test_*.py' -v
