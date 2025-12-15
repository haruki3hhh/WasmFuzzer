FL_PYTHON_ONLY=1 AFL_PYTHON_MODULE="pymodules.python-main" PYTHONPATH=. ./afl-fuzz -i ./pymodules/samples -o ./fuzz_out \
	/root/wasm-micro-runtime/product-mini/platforms/linux/build/iwasm \
	@@