PORT?=8008

test:
	python setup.py test

docs:
	cd docs && $(MAKE) html

docs-server: docs
	(sleep 1 && sensible-browser "http://localhost:$(PORT)")
	cd docs/_build/html/ && python -m SimpleHTTPServer $(PORT)

.PHONY: test docs docs-server
