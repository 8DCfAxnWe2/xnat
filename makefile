
xnat: main.c tcppeer.c udppeer.c array.c common.c route.c dns.c hostrule.c
	gcc -o bin/$@ $^ -std=c11 -Wall -D _GNU_SOURCE -O3
