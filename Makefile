all: external/openssl/build/lib/libssl.a client.exe module.dll

external/openssl/build/lib/libssl.a:
	sudo apt-get install mingw-w64
	chmod +x external/openssl/Configure
	cd external/openssl &&\
		./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=$(shell pwd)/external/openssl/build &&\
		make && sudo make install

client.exe: client.c
	x86_64-w64-mingw32-gcc client.c -static -I external/openssl/build/include/ -o client.exe -Lexternal/openssl/build/lib/ -lcrypto -lssl -lgdi32 -lwsock32 -lws2_32 -lkernel32
	
module.dll: module.c
	x86_64-w64-mingw32-gcc module.c -static -shared -o module.dll
