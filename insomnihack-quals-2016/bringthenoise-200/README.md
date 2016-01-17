INSOMNIHACK QUALIFIERS 2016 : Bring the Noise

Category: Crypto
Points: 200
Solves:

Description:
  Quantum computers won't help you
  Source
  Running on: bringthenoise.insomnihack.ch:1111

Writeup:
  A quick look at the provided source code shows us that the flag will be printed upon meeting two conditions. First, 5 random bytes are provided,
  and we must create a string whose first 5 bytes match after being hashed using md5. Since 5 bytes is a very small size, it's very simple to brute
  force this and send it back to the server.

  Next, 40 lists of numbers are provided, with the prompt: 'Enter solution as "1, 2, 3, 4, 5, 6"'
  Another look at the source shows us that these lists are generated by learn_with_vibrations(), along with the key to the flag.
  We can see that both the key and the first 6 numbers in the lists are generated randomly - however, the last number in each list is generated via some modular arithmetic.
  Working backwards, we just need to find a set of 6 numbers to multiply with the first 6 numbers in each list given, that could yield the 7th number.
  
  This is just a matter of replicating the operations - multiplying numbers with corresponding indices, taking the sum of all 6 products, taking that modulo 8, and then shifting it -1, 0, or 1
  Doing this for all 40 lists will give you about 3.5 million possible keys - finding the real one is just a matter of checking for the list that appears 40 times.
  Sending this to the server yields the flag: INS{ErrorsOccurMistakesAreMade}

Python Code:
(Time constraints for this one were pretty strict, so this is really shitty code - sorry)

import hashlib, os, struct, socket, itertools, operator
from random import randint

def most_common(guesslist):
  sortedguesslist = sorted((x, i) for i, x in enumerate(guesslist))
  gr = itertools.groupby(sortedguesslist, key=operator.itemgetter(0))
  def iterlist(g):
    item, iterable = g
    count = 0
    min_index = len(guesslist)
    for _, where in iterable:
      count += 1
      min_index = min(min_index, where)
    return count, -min_index
  return max(gr, key=iterlist)[0]

def guess(t, r):
    result = int(r)
    v = []
    for x in t:
        v.append(int(x))
    guesslist = []
    for i in range(0,8):
        for j in range(0,8):
            for k in range(0,8):
                for l in range(0,8):
                    for m in range(0,8):
                        for n in range(0,8):
                            if (i*v[0] + j*v[1] + k*v[2] + l*v[3] + m*v[4] + n*v[5]) % 8 in [result-1, result, result+1]:
                                guesslist.append([i, j, k, l, m, n])
    return guesslist

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('bringthenoise.insomnihack.ch', 1111))
msg = s.recv(1024)
challenge = msg.split(" = ")[1]
print challenge.split("\n")[0].strip()
while 1:
    x = str(struct.unpack('<L', os.urandom(4))[0])
    t = hashlib.md5(x).hexdigest().strip()
    if t[:5] == challenge.split("\n")[0].strip():
        a = x
        break
print a
s.send(a+"\n")

z = []
for i in range(40):
    f = s.recv(20).split("\n")[0]
    print f
    z.append(f)
print s.recv(1024)

guesses = []
for j in z:
    vector = j.split(", ")
    possiblekeys = guess(vector[0:6], vector[6])
    guesses.append(possiblekeys)
flatguesses = [item for sublist in guesses for item in sublist]
key = most_common(flatguesses)
s.send(str(key)[1:-1]+"\n")
print s.recv(1024)