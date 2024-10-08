
all: windows linux

windows: certinfo.exe

linux: certinfo


clean:
	rm -f *~
	rm -f .*~

distclean: clean
	rm -f certinfo.exe
	rm -f certinfo
certinfo.exe: main.go info/info.go
	go build

certinfo: main.go info/info.go
	env GOOS=linux GOARCH=amd64 go build

test: 
	cd info; go test
