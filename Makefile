LIBPCAP=-lpcap
LIBNET=-lnet

tracy: tracy.c
	$(CC) -o $@ $< $(LIBPCAP) $(LIBNET)
