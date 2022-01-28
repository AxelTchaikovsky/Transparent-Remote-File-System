# Transparent Remote File System

15-440 Spring 2022

## Description

A server process to provide the remote file services.

A client stub library to perform RPCs.

The system is able to handle the following standard C library calls: ```open```, ```close```, ```read```, ```write```, ```lseek```, ```stat```, ```unlink```, ```getdirentries``` and the non-standard ```getdirtree``` and ```freedirtree``` calls.

Hard coded all the marshalling and unmarshalling of parameters and return values, did not use libraries. 

## Environment
Because this project uses precompiled libraries and 
binaries, it will only run on 64-bit x86 Linux machines.
(e.g., Andrew unix servers; it won't run on Windows or
Mac, unless you run 64-bit Linux in a VM).  

## Usage
The tcp-sample directory has a sample code for a simple
server and client.

For the main system implementation, navigate into the ```/interpose``` directory which has code for creating a
interposition library and a remote server handling different remote procedure calls (RPCs).

Run ```make``` in the ```/interpose``` directory to build 
the programs.

First run ```./server``` on the remote server by

```
./server
```

Run the RPCs on your local client (Examples)
```
LD_PRELOAD=./mylib.so ../tools/440cat foo
```
```
cat foo | LD_PRELOAD=./mylib.so ../tools/440write bar
```
```
export LD_LIBRARY_PATH=../lib/

LD_PRELOAD=./mylib.so ../tools/440tree .. > foo
```

The tools directory has a few programs we will be using to 
test your code.  These are binary-only tools that operate
on the local filesystem.  You will make them operate across
the network by interposing on their C library calls.  Run
any of these tools without arguments for a brief message on 
how to use it.  These binaries should work on x86 64-bit 
Linux systems (e.g., unix.andrew.cmu.edu servers).  

To use the interposing library, try (if using BASH shell):
	LD_PRELOAD=./interpose/mylib.so ./tools/440read README
or (if using CSH, TCSH, ...):
	env LD_PRELOAD=./interpose/mylib.so ./tools/440read README

Note that the 440tree tool uses the getdirtree function 
implemented in libdirtree.so in the lib directory.  Please
add the absolute path of this directory to LD_LIBRARY_PATH
to make sure that the system can find the library, e.g. on BASH:
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH;$PWD/lib"
or if using CSH, TCSH, ...:
	setenv LD_LIBRARY_PATH "$LD_LIBRARY_PATH;$PWD/lib"


