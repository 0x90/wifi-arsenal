

gcc -I./ -o api_test.o -c api_test.c -g
gcc -o apitest api_test.o -lorcon -lnl -lpcap
