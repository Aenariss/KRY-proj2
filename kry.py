## KRY Projekt 2 - Client code
## Author: Vojtech Fiala <xfiala61>

from sys import argv, stderr
from re import search
from server import startServer
from client import startClient


def errorPrint(str):
    stderr.write(str + '\n')
    exit(1)

def parseArgs():

    if len(argv) != 3: # only 2 args + program name allowed
        errorPrint("Invalid number of arguments!")
    # check if args seem ok
    arg1 = search("^(c|s)$", argv[1])
    arg2 = search("^[0-9]{1,5}$", argv[2])
    if (not arg1) or (not arg2):
        errorPrint("Invalid arguments!")

    mode = arg1[0]
    port = arg2[0]

    return mode, int(port)

def main():
    mode, port = parseArgs()
    if mode == "s":
        startServer(port)
    elif (mode == "c"):
        startClient(port)
    else:
        errorPrint("This should never happen!")

if __name__ == "__main__":
    main()