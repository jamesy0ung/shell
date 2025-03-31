CC = gcc
CFLAGS = -W -Wall -Wextra -pedantic -std=c11
TARGET = shell
SRCS = main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

asan: CC = clang
asan: CFLAGS += -fsanitize=address -fno-omit-frame-pointer -g
asan: $(TARGET)

clean:
	rm -f $(TARGET)
