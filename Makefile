all: Test

#%.o: %.c
#       $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
Test: main.o
	$(CC) -o $@ $^ $(LDFLAGS) -lpthread -lcrypto

clean:
	rm -rf *.o
