FILES = keygen lock unlock

#all: $(FILES)

# %: %.py
# 	echo "#!/bin/bash \npython ./$< \$$1 \$$2 \$$3 \$$4 \$$5 \$$6 \$$7 \$$8" >$@
# 	chmod +x $@

all: keygen.py lock.py unlock.py
	cp keygen.py keygen
	chmod +x keygen.py
	cp lock.py lock
	chmod +x lock.py
	cp unlock.py unlock
	chmod +x unlock.py

# lock: lock.py
# 	cp lock.py lock
# 	chmod +x lock

clean:
	rm -f $(FILES)
