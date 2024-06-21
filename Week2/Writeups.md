# Writeups for CSOC-week 2

---

# Cryptography

---

## 1. <mark> INTRODUCTION

- ## <mark> Finding Flags
  
  #### Writeup :

  Just submit the flag **crypto{y0ur_f1rst_fl4g}** and the first challenge is done.

- ## <mark> Great Snakes
  
    ### Challenge description :

    Run the attached Python script and it will output your flag.

    [Challenge file](https://cryptohack.org/static/challenges/great_snakes_35381fca29d68d8f3f25c9fa0a9026fb.py)

    ### Writeup :

    I made a bash script `great_snakes.sh`.

    ```sh
    #!/bin/bash

    # Declaring the given challenge file as myfile
    myfile="great_snakes_35381fca29d68d8f3f25c9fa0a9026fb.py"

    # Executing myfile and storing the message in flag
    flag="$(./$myfile)"

    # printing flag
    echo $flag
    ```

    Then changed its mode using `chmod +x great_snakes.sh`, executed it using `./great_snakes.sh` and got the flag **crypto{z3n_0f_pyth0n}**.

- ## <mark> Network Attacks
  
    ### Challenge description :

    For this challenge, connect to `socket.cryptohack.org` on port `11112`. Send a JSON object with the key `buy` and value `flag`.

    [Challenge file](https://cryptohack.org/static/challenges/pwntools_example_72a60ff13df200692898bb14a316ee0b.py)

    ### Writeup :

    In the description it was told to send the JSON object with the key    `buy` and value `flag`. But in the challenge file its value was `clothes`. So, it wasn't executing properly. Then I modified the script given by replacing **clothes** with **flag** and made this one named `pwntools_example.py` -

    ```py
    #!/usr/bin/env python3

    from pwn import * # pip install pwntools
    import json

    HOST = "socket.cryptohack.org"
    PORT = 11112

    r = remote(HOST, PORT)


    def json_recv():
        line = r.readline()
        return json.loads(line.decode())

    def json_send(hsh):
        request = json.dumps(hsh).encode()
        r.sendline(request)


    print(r.readline())
    print(r.readline())
    print(r.readline())
    print(r.readline())

    # Just converted "clothes" into "flag"
    request = {
        "buy": "flag"
    }
    json_send(request)

    response = json_recv()

    print(response)

    ```

    Then run it using `./pwntools_example.py`. It connected to the server and gave the flag **crypto{sh0pp1ng_f0r_fl4g5}**.


## 2. <mark> GENERAL

- ## <mark> ENCODING

  - ## <mark> ASCII
    
    ### Challenge description :

    Using the below integer array, convert the numbers to their corresponding ASCII characters to obtain a flag.
    
    `[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]`

    ### Writeup :
    
    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the list of integers
    list = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

    # Converting each integer into its corresponding character and appending into flag
    flag = ''.join(chr(n) for n in list)

    # Printing the flag
    print(flag)
    ```

    Output : **crypto{ASCII_pr1nt4bl3}**

  - ## <mark> Hex
  
    ### Challenge description :

    Included below is a flag encoded as a hex string. Decode this back into bytes to get the flag.

    `63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d`

    ### Writeup :

    Script :

    ```sh
    #!/bin/bash

    # Declaring the input string
    input_string="63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"

    # Decoding the string into bytes
    flag=$(echo $input_string | xxd -r -p)

    # Printing the flag
    echo $flag
    ```

    Output : **crypto{You_will_be_working_with_hex_strings_a_lot}**

  - ## <mark> Base64
    
    ### Challenge description :

    Take the below hex string, decode it into bytes and then encode it into Base64.

    `72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf`

    ### Writeup :

    Script :

    ```sh
    #!/bin/bash

    # Declaring the input string
    input_string="72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

    # Decoding the string into bytes and encoding into base64
    flag=$(echo $input_string | xxd -r -p | base64)

    # printing the flag
    echo $flag
    ```

    Output : **crypto/Base+64+Encoding+is+Web+Safe/**

  - ## <mark> Bytes and Big Integers

    ### Challenge description :

    Convert the following integer back into a message:

    `11515195063862318899931685488813747395775516287289682636499965282714637259206269`

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the input integer
    input_int = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

    # Converting the integer into hex string
    enc_str = str(hex(input_int))

    # excluding the notation "0x" from the string
    enc_str = enc_str[2:]

    # Declaring the list int_list
    int_list = []

    i = 0

    # Decoding each bytes of the hex string into decimal
    # and appending in the list
    while i<=len(enc_str) - 1:
        int_list.append(int(enc_str[i:i+2], 16))
        i += 2

    # Converting each integer into its corresponding character
    # and appending into flag
    flag = ''.join(chr(n) for n in int_list)

    print(flag)

    ```

    Output : **crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}**

- ## <mark> XOR
  
  - ## <mark> XOR Starter

    ### Challenge description :

    Given the string `label`, XOR each character with the integer `13`. Convert these integers back to a string and submit the flag as `crypto{new_string}`.

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the input string and the integer
    _str = "label"
    _int = 13

    # Declaring a new string
    new_str = ""

    # Decoding the input string and appending into the new string
    for i in _str:
        new_str += chr(ord(i) ^ _int)

    print(new_str)
    ```

    Output : **aloha**

    Hence, the flag will be **crypto{aloha}**.

  - ## <mark> XOR Properties

    ### Challenge description :

    Below is a series of outputs where three random keys have been XOR'd together and with the flag. Use the above properties to undo the encryption in the final line to obtain the flag.

    ```
    KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
    KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
    KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
    FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf
    ```

    ### Writeup :
    
    Script :

    ```py
    #!/usr/bin/env python3

    from Crypto.Util.number import *

    # Declaring the necessary keys
    k1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
    # Let k4 = k2 ^ k3
    k4 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
    # Let k5 =flag ^ k1 ^ k2 ^ k3
    k5 = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

    # Converting the hex values into bytes
    k1_bytes = bytes.fromhex(k1)
    k4_bytes = bytes.fromhex(k4)
    k5_bytes = bytes.fromhex(k5)

    # Converting the bytes into long integers
    k1_long = bytes_to_long(k1_bytes)
    k4_long = bytes_to_long(k4_bytes)
    k5_long = bytes_to_long(k5_bytes)

    # Finding the flag in long integer.
    # Since, flag ^ k1 ^ k3 ^ k2 =  k5 => flag ^ k1 ^ k4 = k5 => flag = k1 ^ k4 ^ k5
    flag_long = k1_long ^ k4_long ^ k5_long

    # Converting the flag into bytes
    flag_bytes = long_to_bytes(flag_long)

    print(flag_bytes)

    ```

    Output : **b'crypto{x0r_i5_ass0c1at1v3}'**

    Thus we get the flag **crypto{x0r_i5_ass0c1at1v3}**.

  - ## <mark> Favourite byte

    ### Challenge description :

    I've hidden some data using XOR with a single byte, but that byte is a secret. Don't forget to decode from hex first.

    `73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d`

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the hex string
    str_hex = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"

    # Converting it into bytes
    str_bytes = bytes.fromhex(str_hex)

    # Brute-forcing the keys from 0-255 
    for key in range(256):
        flag = "".join(chr(key ^ i)  for i in str_bytes)
        # Using the flag format to find the correct flag.
        if "crypto" in flag:
            # Printing the key and the flag
            print(key, flag)

    ```

    Output : **16 crypto{0x10_15_my_f4v0ur173_by7e}**

    So, the correct key is `16` and the flag is **crypto{0x10_15_my_f4v0ur173_by7e}**.

  - ## <mark> You either know, XOR you don't

    ### Challenge description :

    I've encrypted the flag with my secret key, you'll never be able to guess it.

    `0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104`

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    from pwn import *

    # Declaring the encrypted data in bytes
    input_str = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")

    # We know the first 7 characters of the flag
    flag_format = "crypto{"

    # Decrypting the first 7 characters of the key
    key = xor(input_str[:7], flag_format)
    # Thus got the key 'myXORke'
    # By intuition appended 'y' at the end of the key

    key += b'y' 

    # Again XOR the input string with the key
    flag = xor(input_str, key)

    print(flag)

    ```

    Output : **b'crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}'**

- ## <mark> MATHEMATICS

  - ## <mark> Greatest Common Divisor

    ### Challenge description :

    Now calculate `gcd(a,b)` for `a = 66528`, `b = 52920` and enter it below.

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the function gcd
    def gcd(a,b):	
        while a != b:
            # Substracting the larger number from the smaller one
            if a > b:
                a -= b
            else:
                b -= a
        # When the two numbers become equal return any of them
        return a


    # Calling the function gcd 
    ans = gcd(66528,52920)

    # Printing the answer
    print(f"The gcd of the given two numbers is: {ans}")
    ```

    Output : The gcd of the given two numbers is: **1512**

  - ## <mark> Extended GCD

    ### Challenge description :

    Using the two primes `p = 26513, q = 32321`, find the integers `u,v` such that
    `p * u + q * v = gcd(p,q)`

    Enter whichever of `u` and `v` is the lower number as the flag.

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    def extended_gcd(p, q):
        # Defining the base case
        if p == 0:
            # gcd is 'q', and coefficient of p is 0 and q is 1
            return q, 0, 1
        
        # Calculating gcd and the coefficients u1, v1 for the smaller problem
        gcd, u1, v1 = extended_gcd(q % p, p)
        
        # Updating u and v using u1 and v1
        u = v1 - (q // p) * u1
        v = u1
        
        # Returning gcd and the updated coefficients
        return gcd, u, v



    # Calling the function extended_gcd to get the final gcd and coefficients
    gcd, u, v = extended_gcd(26513, 32321)

    # Printing the results
    print(f"The minumum of u and v is {min(u,v)}")

    ```

    Output : The minumum of u and v is **-8404**

  - ## <mark> Modular Arithmetic 1

    ### Challenge description :

    Calculate the following integers:

    ```
    11 ≡ x mod 6
    8146798528947 ≡ y mod 17
    ```

    The solution is the smaller of the two integers.

    ### Writeup :

    Script : 

    ```py
    #!/usr/bin/env python3

    def modulo(a, b):
        # Ensuring that a and b are positive
        a, b = abs(a), abs(b)
        
        # Raising value error in case b is zero to avoid division by zero
        if b == 0:
            raise ValueError("The divisor b cannot be zero")
        
        # Returning the remainder of a and b
        return a % b

    try:
        # Calling the modulo function for the two test cases provided
        x = modulo(11,6)
        y = modulo(8146798528947,17)

        # Printing the minimum value between x and y
        print(f"The minimum remainder is {min(x,y)}")

    # Printing the message in case of value error
    except ValueError as msg:
        print(msg)

    ```

    Output : The minimum remainder is 4

  - ## <mark> Modular Arithmetic 2

    ### Challenge description :

    Now take the prime `p = 65537`. Calculate `273246787654 ^ 65536 mod 65537`.

    ### Writeup :

    ***Fermat's little theorem***: If p is a prime number and a is not divisible by p, then a^(p-1) mod p = 1

    Script : 

    ```py
    #!/usr/bin/env python3

    from sympy import isprime

    # Defining the function fermat
    def fermat(a,p):
        # If a and p satisfy the conditions then return 1
        if isprime(p) and a%p != 0:
            return 1
        else:
            return 0

    # Declaring the variables a and p
    a = 273246787654
    p = 65537

    # Calling the function fermat
    ans = fermat(a,p)

    if ans == 1:
        print(f'{a} ^ {p-1} mod {p} = {ans}')
    else:
        print(f"{a} and {p} does not satisfy fermat's theorem conditions.")

    ```

    Output : 273246787654 ^ 65536 mod 65537 = 1

  - ## <mark> Modular Inverting

    ### Challenge description :

    What is the inverse element: `3 * d ≡ 1 mod 13`?

    ### Writeup :

    The expression for modular inverse is `g * d ≡ 1 mod p`. Now for finding `d` using `g` and `p`, we can modify the expression as:

    g * d ≡ 1 mod p

    => g * d mod p = 1

    => g * d = i * p + 1; for some quotient i

	=> d = (i * p + 1)/g

    Here we can start i from 0 and increment it by 1 until we find its correct value.

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the function modular_inverse
    def modular_inverse(g,p):
        i = 0
        # Finding the correct value of i
        while  (i*p+1)%g != 0:
            i += 1
        # Returning the value of d
        return (i*p+1)//g

    # Declaring the variables g and p
    g = 3
    p = 13

    # Calling the function modular_inverse
    d = modular_inverse(g,p)

    print(f'The modular inverse of {g} modulo {p} is {d}')
    ```
    Output : The modular inverse of 3 modulo 13 is 9

## 3. <mark> SYMMETRIC CIPHERS

- ## <mark> HOW AES WORKS

  - ## <mark> Keyed Permutations
    
    ### Challenge description :

    What is the mathematical term for a one-to-one correspondence?

    ### Writeup :

    One-to-one means both injective(one-one) and surjective(onto) that is bijective. Hence, the mathematical term for a one-to-one correspondence is bijection. So, the flag for this challenge is **crypto{bijection}**.

  - ## <mark> Resisting Bruteforce

    ### Challenge description :

    What is the name for the best single-key attack against AES?

    ## Writeup :
    The answer is Biclique. So, the flag is **crypto{biclique}**.

  - ## <mark> Structure of AES

    ### Challenge description :

    Included is a `bytes2matrix` function for converting our initial plaintext block into a state matrix. Write a `matrix2bytes` function to turn that matrix back into bytes, and submit the resulting plaintext as the flag.

    [Challenge file](https://cryptohack.org/static/challenges/matrix_e1b463dddbee6d17959618cf370ff1a5.py)

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the function matrix2bytes with matrix as an argument
    def matrix2bytes(matrix):
        flag = ''
        # Decrypting each element of the 4x4 matrix and appending into flag
        for x in range(len(matrix)):
            for y in range(len(matrix[x])):
                flag += chr(matrix[x][y])
        # Returning the flag
        return flag

    # Declaring the matrix
    matrix = [
        [99, 114, 121, 112],
        [116, 111, 123, 105],
        [110, 109, 97, 116],
        [114, 105, 120, 125],
    ]

    # Calling the function matrix2bytes and printing the flag
    print(matrix2bytes(matrix))
    ```

    Output : **crypto{inmatrix}**

## 4. <mark> RSA

- ## <mark> STARTER

  - ## <mark> RSA Starter 1
    
    ### Challenge description :

    Find the solution to `101 ^ 17 mod 22663`

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the variables
    base = 101
    exp = 17
    mod = 22663

    # Calling the built-in pow function
    ans = pow(base,exp,mod)

    # Printing the answer
    print(ans)
    ```

    Output : **19906**

  - ## <mark> RSA Starter 2
    
    ### Challenge description :

    "Encrypt" the number `12` using the exponent `e = 65537` and the primes `p = 17` and `q = 23`. What number do you get as the ciphertext?

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the variables
    msg = 12
    e = 65537
    p = 17
    q = 23

    # Computing N
    N = p * q

    # Computing the ciphertext
    ct = pow(msg,e,N)

    print(f"The ciphertext is {ct}")
    ```

    Output : The ciphertext is 301

    So, the number is **301**.

  - ## <mark> RSA Starter 3
    
    ### Challenge description :

    Given `N = p*q` and two primes:

    `p = 857504083339712752489993810777`

    `q = 1029224947942998075080348647219`

    What is the totient of `N`?

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the variables
    p = 857504083339712752489993810777
    q = 1029224947942998075080348647219
    N = p * q

    # Computing totient of N or phi
    phi = (p-1) * (q-1)

    print(f'Totient of N is {phi}')
    ```

    Output : Totient of N is **882564595536224140639625987657529300394956519977044270821168**

  - ## <mark> RSA Starter 4

    ### Challenge description :

    Given the two primes:

    `p = 857504083339712752489993810777`

    `q = 1029224947942998075080348647219`

    and the exponent:

    `e = 65537`

    What is the private key `d`?

    ### Writeup :

    In RSA the **private key** is the **modular multiplicative inverse of the exponent e modulo the totient of N**. This implies `e * d ≡ 1 mod phi` => `d = e ^ (-1) mod phi`

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the variables
    p = 857504083339712752489993810777
    q = 1029224947942998075080348647219
    e = 65537

    # Computing totient of N
    phi = (p-1) * (q-1)

    # Computing d
    d = pow(e,-1,phi)

    # Printing d
    print(f'The private key d is {d}')
    ```

    Output : The private key d is **121832886702415731577073962957377780195510499965398469843281**

  - ## <mark> RSA Starter 5

    ### Challenge description :

    I've encrypted a secret number for your eyes only using your public key parameters:

    `N = 882564595536224140639625987659416029426239230804614613279163`

    `e = 65537`

    Use the private key that you found for these parameters in the previous challenge to decrypt this ciphertext:

    `c = 77578995801157823671636298847186723593814843845525223303932`

    ### Writeup :

    The private key, d = 121832886702415731577073962957377780195510499965398469843281

    So, if the secret number is m, then `m = c ^ d mod N`.

    Script :

    ```py
    #!/usr/bin/env python3

    # Declaring the variables
    N = 882564595536224140639625987659416029426239230804614613279163
    c = 77578995801157823671636298847186723593814843845525223303932
    d = 121832886702415731577073962957377780195510499965398469843281

    # Computing the secret number
    m = pow(c,d,N)

    # Printing the secret number
    print(f'The secret number is {m}')
    ```

    Output : The secret number is **13371337**

  - ## <mark> RSA Starter 6

    ### Challenge description :
    
    Sign the flag `crypto{Immut4ble_m3ssag1ng}` using your private key and the SHA256 hash function.

    [Challenge file](https://cryptohack.org/static/challenges/private_0a1880d1fffce9403686130a1f932b10.key)

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    import hashlib
    from Crypto.Util.number import *

    # Defining the function hash_message
    def hash_message(message):
        # Creating a new SHA-256 hash object
        sha256_hash = hashlib.sha256()
        
        # Update the hash object with the bytes of the message
        # Ensure the message is encoded to bytes
        sha256_hash.update(message.encode('utf-8'))
        
        # Retrieve the hexadecimal representation of the hash
        hash_hex = sha256_hash.hexdigest()
        return hash_hex


    # Declaring the variables
    message = "crypto{Immut4ble_m3ssag1ng}"
    N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803
    d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689

    # Converting the hex hash into bytes
    hashed_message = bytes.fromhex(hash_message(message))
    # Converting from bytes to long integer
    H = bytes_to_long(hashed_message)

    # Signing the message using the hash
    sign = pow(H,d,N)

    # Printing the sign
    print(sign)
    ```

    Output : 13480738404590090803339831649238454376183189744970683129909766078877706583282422686710545217275797376709672358894231550335007974983458408620258478729775647818876610072903021235573923300070103666940534047644900475773318682585772698155617451477448441198150710420818995347235921111812068656782998168064960965451719491072569057636701190429760047193261886092862024118487826452766513533860734724124228305158914225250488399673645732882077575252662461860972889771112594906884441454355959482925283992539925713424132009768721389828848907099772040836383856524605008942907083490383109757406940540866978237471686296661685839083475


- ## <mark> PUBLIC EXPONENT

  - ## <mark> Salty
    
    ### Challenge description :

    Smallest exponent should be fastest, right?

    ### Challenge files:

    [salty.py](https://cryptohack.org/static/challenges/salty_9854bdcadc3f8b8f58008a24d392c1bf.py)

    [output.txt](https://cryptohack.org/static/challenges/output_95f558e889cc66920c24a961f1fb8181.txt)

    ### Writeup :

    Script :

    ```py
    #!/usr/bin/env python3

    from Crypto.Util.number import inverse, long_to_bytes

    # Declaring the variables
    n = 110581795715958566206600392161360212579669637391437097703685154237017351570464767725324182051199901920318211290404777259728923614917211291562555864753005179326101890427669819834642007924406862482343614488768256951616086287044725034412802176312273081322195866046098595306261781788276570920467840172004530873767                                                                  
    e = 1
    ct = 44981230718212183604274785925793145442655465025264554046028251311164494127485

    # Calculating the totient of N(phi), private key(d)
    phi = (n-1)
    d = inverse(e,phi)

    # Decrypting the ciphertext
    pt = pow(ct, d, n)
    decrypted = long_to_bytes(pt)

    # Printing the plaintext
    print(decrypted)
    ```

    Output : b'crypto{saltstack_fell_for_this!}'


---


## 5. <mark> challenge_1

### Challenge files :

[source.enc](https://github.com/JustAnAverageGuy/literate-octo-fiesta/blob/main/challenge_1/source.enc)

[output.txt](https://github.com/JustAnAverageGuy/literate-octo-fiesta/blob/main/challenge_1/output.txt)

### Writeup :

The `source.enc` file contained **base64** encoded data. So I decoded the data from [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=ZDJsMGFDQnZjR1Z1S0NkbWJHRm5MblI0ZENjc0lDZHlKeWtnWVhNZ1pqb0tJQ0FnSUdac1lXY2dQU0JtTG5KbFlXUW9LUW9LY3lBOUlDY25MbXB2YVc0b1ptOXliV0YwS0c5eVpDaHBLU3dnSnpBeWVDY3BJR1p2Y2lCcElHbHVJR1pzWVdjcENtVWdQU0FpSWdvS1ptOXlJR2tnYVc0Z2NtRnVaMlVvTUN4c1pXNG9jeWtzTkNrNkNpQWdJQ0JsSUNzOUlHWnZjbTFoZENocGJuUW9jMXRwT21rck1sMHNNVFlwWG1sdWRDaHpXMms2YVNzMFhTd3hOaWtzSUNjd01uZ25LUW9LZDJsMGFDQnZjR1Z1S0NkdmRYUndkWFF1ZEhoMEp5d2dKM2NuS1NCaGN5Qm1PZ29nSUNBZ1ppNTNjbWwwWlNobEtRPT0) and found this script:

```py
with open('flag.txt', 'r') as f:
    flag = f.read()

s = ''.join(format(ord(i), '02x') for i in flag)
e = ""

for i in range(0,len(s),4):
    e += format(int(s[i:i+2],16)^int(s[i:i+4],16), '02x')

with open('output.txt', 'w') as f:
    f.write(e)
```

And the file `output.txt` contained hex data. So I made this script to decode it:

```py
#!/usr/bin/env python3

# Opening the file 'output.txt' in read mode and reading its contents in the variable output
with open('output.txt','r') as f:
    output = f.read()

# Declaring flag_hex
flag_hex = ""

# Performing the same encoding scheme that was used to encode the flag to decode the output and store it in flag_hex
for i in range(0,len(output),4):
    flag_hex += format(int(output[i:i+2],16)^int(output[i:i+4],16), '02x')

# Converting the hex data into bytes
flag_bytes = bytes.fromhex(flag_hex)

# Printing flag_bytes
print(flag_bytes)
```

Output: b'CSOC23{345y_ba5364_4nd_x0r?}'

And we got the flag **CSOC23{345y_ba5364_4nd_x0r?}**.
