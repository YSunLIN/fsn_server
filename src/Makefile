fsn_server: dial.o xprotocol.o dprotocol.o md5.o public.o
	$(CC) $^ -g -o $@ -lpthread

dial.o: dial.c dial.h xprotocol.h public.h md5.h
	$(CC) -c -std=c99  dial.c -o  $@
dprotocol.o: dprotocol.c dprotocol.h public.h
	$(CC) -c -std=c99  dprotocol.c -o  $@
xprotocol.o: xprotocol.c xprotocol.h public.h md5.h
md5.o: md5.c md5.h
public.o: public.c public.h

clean:
	rm -rf *.o fsn_server

.PHONY: clean
	
