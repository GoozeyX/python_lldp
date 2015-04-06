import os

with open("textfile") as f:
    data = f.read()
    print f
print "now outside with block"
print f
