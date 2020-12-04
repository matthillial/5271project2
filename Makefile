FILES = keygen lock unlock


all: keygen.py lock.py unlock.py
	# install pycryptodome module to python 3.8
	pip3 install pycryptodome
	cp keygen.py keygen
	chmod +x keygen
	cp lock.py lock
	chmod +x lock
	cp unlock.py unlock
	chmod +x unlock


clean:
	rm -f $(FILES)
