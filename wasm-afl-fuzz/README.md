# WASM FUZZ Doc

## ENV Setup
You can execute `recompile.sh`, before it, you may need to install python 3.8 and related lib.

## Usage
### Code Dir
In `AFL-WASM/pymodules`:
1. `pymodules/python-main`: main python file, interact with AFL. 
2. `pymodules/wasm`: wasm parser.
3. `pymodules/mutator`: wasm mutation.
4. `pymodules/samples`: 200 wasm files.

### How to run it
You can run `run.sh`.
The wasm runtime path in `run.sh` you can modify to another runtime.  

## Mutator
1. Mutation for wasm file structure.
2. Mutation for wasm instructions.