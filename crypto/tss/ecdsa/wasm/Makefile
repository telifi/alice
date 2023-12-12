main: clean
	GOOS=js GOARCH=wasm go build -o build/wasm.wasm
	mv build/wasm.wasm ../../../../../mpc-lib/example/mpc-wallet/public/mpc.wasm

clean:
	rm -rf ./build
	mkdir ./build
