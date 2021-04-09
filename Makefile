OUT = main
SRC = main.cpp src/civetweb.c src/bcm2835.c src/MFRC522.cpp src/request.cpp
CC = g++
CFLAGS = -o
IFLAGS = -Iinc
LFLAGS = -lpthread

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(OUT) $(IFLAGS) $(LFLAGS) $(SRC)
