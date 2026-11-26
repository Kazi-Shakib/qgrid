CFLAGS = -O2 -Wall -Wno-unused-result -pthread
qgrid: main.c crypto.c net.c keynet.c dnp3.c qkdsw.c entities.c qg.h
	$(CC) $(CFLAGS) -o qgrid main.c crypto.c net.c keynet.c dnp3.c qkdsw.c entities.c -lssl -lm -lcrypto
clean:
	rm -f qgrid
