LIBPCAP=-lpcap
LIBNET=-lnet

tracy: tracy.c
	$(CC) -o $@ $< $(LIBPCAP) $(LIBNET)

clean:
	-rm tracy
