# INTERNETWACHE 2016 : Bank

**Category:** Crypto

**Points:** 90

**Solves:** 48

## Description:

  > Everyone knows that banks are insecure. This one super secure and only allows only 20 transactions per session. I always wanted a million on my account.

  > Attachment: crypto90.zip

  > Service: 188.166.133.53:10061


## Writeup:
  This was an interesting challenge. I found out after spending upwards of two hours doing the modular arithmetic for an exploit that there was a much easier way. However, being a math enthusiast, I still enjoyed this one very much.

  The source is a rather straightforward replica banking system. It has a number generator (Randomizer) and a crypto module (Cipher), along with classes for handling 'transactions' (Account and Transaction). What immediately caught my eye is that three of the four numbers given for encryption are static - generally something that lends itself to vulnerability. Though the fourth number is a 32 bit randomly generated integer, I was confident that I could reverse engineer it through some modular arithmetic.

  From there the idea was to use the four crypto numbers to generate a fake verification code which when run through the Cipher.decrypt method, would yield the string "TRANSACTION:99999" and grant me 99999 (dollars, I assume). Preliminary testing on a local copy confirmed that this plan would work if I had a copy of the original cipher seed, so I started doing the math.

  The two important cryptographic functions are:
```
ct += chr( ord(c) ^ (self.__r.get_next() % 2**7) )
```
  and
```
def get_next(self):
  self._x = (self._a*self._x + self._c) % self._m
  return self._x
```
  where ```a = 1664525```, ```c = 1013904223```, ```m = 2^32```, and ```x = int(os.urandom(32).encode('hex'),16)```. ```ct``` is the ciphertext that we want to spoof and it uses ```get_next``` method, but takes the result mod 2^7. First, note that since anything mod 2^7 is congruent mod 2^32, ```m``` is irrelevant for the purposes of this service. Next, we note that if ```y = ax+c mod n```, ```x = a^-1 * (y-c) mod n```. Since ```x = a*x+c mod 2^7```, we know how to derive previous version of ```x```, mod 2^7, given the last version of x.

  We can see in the Cipher.encrypt method that the ciphertext is padded to a length of 17 by ```s += chr(0x09)*(17-l)```, and that the last character will be ```0x09``` or ```\t``` as long as our transaction amount is less than 4 digits. When we enter ```create 20``` into the service it'll give us ciphertext that we can use knowing that the last character encoded was definitely a ```\t```. With this information we can hex decode the ciphertext, re-XOR the last character with ```\t```, and take the answer mod 2^7 to give us the last value of x compute. Then we can iterate the modular arithmetic process we derived earlier 17 times to get the original value of ```x``` in mod 2^7.

  Finally, to generate a new ciphertext, we just take the same steps as the service but with our own amount. We take the string ```"TRANSACTION:99999"``` (or anything 50000 and up) and XOR each character with the result of the same modular arithmetic operations in the source code: (a*x + c) mod n. We have the first value of x, and we have a, c, and n, and everything is in mod 2^7, so the generated verification code decodes perfectly when sent back to the service. Repeat this enough times and we get the flag: IW{SHUT_UP_AND_T4K3_MY_M000NEYY}

## Python Code:
Connect to the server and request a transaction of 20 via "create 20". Take the verification code given and give it to the script when prompted. Repeat until rich.

```
class bankSim:
    def __init__(self, a, c, m, s):
        self._a = a
        self._c = c
        self._m = m
        self._x = s

    def get_next(self):
        self._x = (self._a*self._x + self._c) % self._m
        return self._x

    def set_x(self, x):
        self._x = x

    def get_x(self):
        return self._x

def modinv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

for attempt in range(20):
    realVerificationCode = raw_input("Enter bank code here: ")
    decoded = realVerificationCode.decode('hex')
    last_x = (ord(decoded[-1]) ^ ord("\t")) % 2**7

    randomizerA = 1664525
    randomizerC = 1013904223

    aInverse = modinv(randomizerA**17, 2**7)
    modSum = 0
    for i in range(17):
        modSum += (randomizerA**i)*randomizerC

    original_x = (aInverse * (last_x - modSum)) % 2**7

    Bank = bankSim(1664525, 1013904223, 2**32, original_x)
    transactionString = "TRANSACTION:99999"

    fakeVerificationCode = ""
    for o in transactionString:
        fakeVerificationCode += chr( ord(o) ^ (Bank.get_next() % 2**7))
    print fakeVerificationCode.encode('hex')
```
