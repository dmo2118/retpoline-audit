CXXFLAGS=-Wall -g

OBJ=retpoline-audit.o
LDLIBS=-lbfd -lopcodes

retpoline-audit: retpoline-audit.o
	$(CXX) $^ $(LDLIBS) -o $@

clean:
	-rm retpoline-audit.o retpoline-audit
