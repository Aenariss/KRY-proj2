## Author: Vojtech Fiala <xfiala61>

CC = python3
TARGET = kry.py

.PHONY: build pack run

build:  
	{ \
	python3 -m venv . ;\
	. ./bin/activate ;\
	pip3 install -r requirements.txt ;\
	}

run:
	{ \
	. ./bin/activate ;\
	$(CC) ./$(TARGET) $(TYPE) $(PORT) ;\
	}

pack:
	zip -r 221701.zip Makefile kry.py client.py server.py utils.py cert requirements.txt dokumentace.pdf
