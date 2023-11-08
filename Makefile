
all: certinfo.exe


clean:
	rm -f certinfo.exe
	rm -f *~

distclean: clean

certinfo.exe: main.go info/info.go
	go build


test: 
	cd info; go test
