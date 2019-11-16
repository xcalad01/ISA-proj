isa-tazatel:
	g++ -g -o isa-tazatel src/* -lresolv

clean:
	rm isa-tazatel

tar:
	tar -zcvf xcalad01.tar src h_sources Makefile manual.pdf README.md
