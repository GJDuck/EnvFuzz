CXX=g++
CC=gcc
CXXFLAGS=-std=c++11 -O2 -Wall

env-fuzz: env-fuzz.cpp

rrCovPlugin.so: rrCovPlugin.cpp
	$(CXX) $(CXXFLAGS) -I . -fPIC -shared -o rrCovPlugin.so rrCovPlugin.cpp

rezzan: rezzan.c
	$(CC) -Wall -Wno-unused-function -fno-builtin -Og -g -fPIC -shared -o rezzan.so rezzan.c

