# Makefile -- Analizador de protocolos
# Análisis forense en redes de computadoras
# Aldo Rodríguez Coreño

CC      = gcc
CFLAGS  = -lpcap `pkg-config --cflags --libs gtk+-2.0 gmodule-2.0 gthread-2.0`
SRC     = main.c callbacks.c
OBJS    = $(SRC: .c = .o)

analizador: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) -fv analizador
