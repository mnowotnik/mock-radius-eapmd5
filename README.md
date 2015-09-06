# README #

A mock RADIUS server using the EAP MD5 authentication protocol.

## Building

* Windows (VS2013)

In VS Developer Command Prompt run:

    nmake /f NMakefile

* Windows (mingw)
~~~~
make -f Make_mingw
~~~~
* Linux
~~~~
make
~~~~
## Testing

Run the building command from before for _test_ target e.g.,

    make test
