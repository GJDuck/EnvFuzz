CXX=g++
CXXFLAGS=-std=c++11 -O2 -Wall

env-fuzz: env-fuzz.cpp

rrCovPlugin.so: rrCovPlugin.cpp
	$(CXX) $(CXXFLAGS) -I . -fPIC -shared -o rrCovPlugin.so rrCovPlugin.cpp

