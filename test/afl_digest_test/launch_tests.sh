if [ "$1" != "keep_comment" ]; then
	screen -d -m afl-fuzz -M main-$HOSTNAME -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 50 -g 0 -G 0

	screen -d -m afl-fuzz -S variant-1 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 50 -g 1 -G 1
	screen -d -m afl-fuzz -S variant-2 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 100 -g 2 -G 2
	screen -d -m afl-fuzz -S variant-3 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 128 -g 3 -G 3
	screen -d -m afl-fuzz -S variant-4 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 300 -g 4 -G 4
	screen -d -m afl-fuzz -S variant-5 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 1000 -g 5 -G 5
else
	screen -d -m afl-fuzz -M main-$HOSTNAME -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 50 -g 0 -G 0 -c 1

	screen -d -m afl-fuzz -S variant-1 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 50 -g 1 -G 1 -c 1
	screen -d -m afl-fuzz -S variant-2 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 100 -g 2 -G 2 -c 1
	screen -d -m afl-fuzz -S variant-3 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 128 -g 3 -G 3 -c 1
	screen -d -m afl-fuzz -S variant-4 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 300 -g 4 -G 4 -c 1
	screen -d -m afl-fuzz -S variant-5 -i inputs/ -o output/ -- ./afl_test -d 1 -l 1 -n 1 -s 1000 -g 5 -G 5 -c 1
fi
