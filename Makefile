
$CFLAGS :=
$LFLAGS :=

all: test.c
	gcc -o rsa -lgcrypt test.c
