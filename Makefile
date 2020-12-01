#!/usr/bin/env python

python_program: lock.py
	cp lock.py lock
	chmod +x lock

clean:
	rm lock
