hw2:
	gcc -g -D_GNU_SOURCE -shared -fPIC -o logger.so hw2.c -ldl -Wno-format-extra-args

clean:
	$(RM) -f logger.so a.out *.txt

.phony: hw2 clean
