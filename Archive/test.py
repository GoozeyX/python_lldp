import os
from pprint import pprint as pp
def mul(a, b):
    return a * b

TASKS1 = [(mul, (i,7)) for i in range(20)]

print TASKS1

if __name__ == '__main__':

    TASKS1 = [(mul, (i,7)) for i in range(20)]

    pp(TASKS1)