myping:myping_16_2.o
		gcc -o myping myping_16_2.o
		
myping_16_2.o:myping_16_2.c

clean: 
	rm -f *.o
	