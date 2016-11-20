FLAGS=-std=c++11
LDLIBS=-lncurses

all: wetalk

wetalk: wetalk.o gui.o udp.o
	g++ $(FLAGS) -o wetalk wetalk.o usriface.o asyncomm.o $(LDLIBS) 

wetalk.o: wetalk.cpp usriface.h
	g++ $(FLAGS) -c wetalk.cpp
	
udp.o: asyncomm.cpp asyncomm.h
	g++ $(FLAGS) -c asyncomm.cpp

gui.o: usriface.cpp usriface.h
	g++ $(FLAGS) -c usriface.cpp

clean:
	rm wetalk wetalk.o usriface.o asyncomm.o