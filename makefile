CXX = g++
CXXFLAGS = -g

all: part2make part3make
	
part2make: part2.o CryptoFunctions.o
	$(CXX) $(CXXFLAGS) /usr/lib64/libcrypto.so.10 -o part2 part2.o CryptoFunctions.o

part3make: part3.o CryptoFunctions.o
	$(CXX) $(CXXFLAGS) /usr/lib64/libcrypto.so.10 -o part3 part3.o CryptoFunctions.o
