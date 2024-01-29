# pyuel

Uses `ctypes` to execute a SHELF.

## Usage

Install the dependecies (just pyelftools and keystone):
```
pip install -r requirements.txt
```

Next, you need to build the payload:
```
cd payload
make
cd ..
```

Then convert it to json:
```
python3 ./pack_shelf.py ./payload/main > ./payload/main.json
```

Finally, you can now use the loader like so:
```
python3 ./loader.py ./payload/main.json
```

## License

GPL2

Linker script in `payload`, came from:
https://github.com/ulexec/SHELF-Loading/blob/master/static-pie.ld
