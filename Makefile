LIBPCAP=-lpcap
LIBNET=-lnet

tracy: tracy.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBPCAP) $(LIBNET)


clean:
	-rm tracy
