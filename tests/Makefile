coverage:
	PYTHONPATH=.:./lib coverage3 run -m pytest tests
	coverage3 html --omit=serles/__main__.py,serles/backends/base.py serles/*.py serles/backends/*.py
