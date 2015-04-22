import os

template = """1st header line
second header line
There are {npeople} people in {nrooms} rooms
and the {ratio} is {large}
""" 
npeople = "lol"
nrooms = "lol"
ratio = "lol"
large = "lol"

context = {
 "npeople":npeople, 
 "nrooms":nrooms,
 "ratio": ratio,
 "large" : large
 } 

with open("out.txt", "w") as myfile:
    myfile.write(template.format(**context))