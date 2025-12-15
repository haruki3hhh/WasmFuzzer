AFL_PYTHON_ONLY=1 AFL_PYTHON_MODULE="pymodules.python-main" PYTHONPATH=. ./afl-fuzz -i ./pymodules/sample_once -o ./once_out \
        -n \
        /root/wasm3/wasm3 \
        @@