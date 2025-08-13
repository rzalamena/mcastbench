BIN     = mcastbench
OBJS    = mcastbench.o

CFLAGS += -Wall -Wextra -Wcast-qual -Wconversion -Warith-conversion
CFLAGS += -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes
CFLAGS += -levent -levent_core
CC     := gcc

.c.o:
	$(CC) $(CFLAGS) -c $<

$(BIN): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@

all: $(BIN)

clean:
	rm -f $(OBJS) $(BIN)
