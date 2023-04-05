## Author: Vojtech Fiala <xfiala61>
# python dodelat virtual environment spousteni
CC = python3
TARGET = kry.py

.PHONY: build pack run

build:  
	echo "Musim dodelat spousteni virtualnichi prostredi a stahnout balicky!"

run:
	@$(CC) ./$(TARGET) $(TYPE) $(PORT)

pack: all
	zip 221701.zip Makefile main.py