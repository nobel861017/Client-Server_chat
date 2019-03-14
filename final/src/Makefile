TARGET=port_register client server
INCLUDE=-I../include
BIN=../bin
FLAG=-g
GCC=gcc
#for c++
#GCC=g++
PORT_REGISTER_OBJS=port_register.o connect.o hash.o
LINE_SERVER_OBJS=server_main.o server.o connect.o common.o
LINE_CLIENT_OBJS=client_main.o client.o connect.o common.o
LIB=-lm -lbsd -lpthread
.PHONY: clean
all: $(TARGET)

%.o: %.cpp
	@echo "making: " $@
	@$(GCC) $< -c $(FLAG) $(INCLUDE)
%.o: %.c
	@echo "making: " $@
	@$(GCC) $< -c $(FLAG) $(INCLUDE)
clean:
	rm -rf *.o
	@for bin in $(TARGET); do \
		echo "rm -rf $(BIN)/$$bin"; \
		rm -rf $(BIN)/$$bin; \
	done
port_register: $(PORT_REGISTER_OBJS)
	@echo "making: " $@
	@$(GCC) -o $(BIN)/$@ $(FLAG) $(INCLUDE) $(PORT_REGISTER_OBJS)
client: $(LINE_CLIENT_OBJS)
	@echo "making: " $@
	@$(GCC) -o $(BIN)/$@ $(FLAG) $(INCLUDE) $(LINE_CLIENT_OBJS) $(LIB)
server: $(LINE_SERVER_OBJS)
	@echo "making: " $@
	@$(GCC) -o $(BIN)/$@ $(FLAG) $(INCLUDE) $(LINE_SERVER_OBJS) $(LIB)

