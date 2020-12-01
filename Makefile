FILES = keygen lock unlock

all: $(FILES)

%: %.py
	echo "#!/bin/bash \npython ./$< \$$1 \$$2 \$$3 \$$4 \$$5 \$$6 \$$7 \$$8" >$@
	chmod +x $@

clean:
	rm -f $(FILES)
