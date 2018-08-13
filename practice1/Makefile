CC=gcc

OBJS=main.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
LDLIBS=-lpcap
TARGET=kicmp
INSTALL_PATH=/home/`whoami`/bin
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

.PHONY: clean install uninstall
clean:
	@rm $(OBJS)
install:
	@cp $(TARGET) $(INSTALL_PATH)/$(TARGET)
uninstall:
	@rm $(INSTALL_PATH)/$(TARGET)
