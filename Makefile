all: send-arp

send-arp: main.o hdr.o
	g++ -o send-arp main.o hdr.o -lpcap

main.o: hdr.h main.cpp
	g++ -c -o main.o main.cpp

hdr.o: hdr.h hdr.cpp
	g++ -c -o hdr.o hdr.cpp

clean:
	rm -f send-arp
	rm -f *.o
