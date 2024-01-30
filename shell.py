import os
import json
import sys
import multiprocessing
from loader import SHELFLoader


def run(sl, args):
    sl.run(args, envv=os.environ)


def main():
    with open(sys.argv[1], 'rb') as f:
        data = json.load(f)
    sl = SHELFLoader(data)

    while True:
        cmd = input('> ').split(' ')
        p = multiprocessing.Process(target=run, args=(sl, cmd))
        p.start()
        p.join()


if __name__ == "__main__":
    main()
