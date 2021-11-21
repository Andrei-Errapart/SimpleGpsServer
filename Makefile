# fixme: very rudimentary makefile :(


GpsServer:	main.cxx
	g++ -g -Wall -o $@ $< -D __USE_BSD -I ../base/include -I ../base/utils -L ../base/utils -lutils -levent

clean:
	rm -f GpsServer
