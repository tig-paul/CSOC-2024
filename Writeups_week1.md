# Writeups for CSOC-week 1

---

# Forensics

---

## 1. <mark>Information

#### Challenge description :

Files can always be changed in a secret way. Can you find the flag?

[Challenge file](https://mercury.picoctf.net/static/7cf6a33f90deeeac5c73407a1bdc99b6/cat.jpg)

#### Writeup :

First of all, I used `file` command to check the actual type of that file. It showed JPEG image data. Then opened it with the image viewer but nothing to search for. After that I searched for metadata that I usuallly do and it showed something interesting:

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image.png)

Finally after decoding the string I got the flag `picoCTF{the_m3tadata_1s_modified}`

## 2. <mark>Matryoshka doll

#### Challenge description :

Matryoshka dolls are a set of wooden dolls of decreasing size placed one inside another. What's the final one?

[Challenge file](https://mercury.picoctf.net/static/5eb456e480e485183c9c1b16952c6eda/dolls.jpg)

#### Writeup :

Firstly, `file dolls.jpg` showed that it actually is a png image. Now, `decreasing size` in the description indicated that the file may be compressed multiple times. So, I used `binwalk dolls.jpg` and it showed that the file contains a zip archive and a png image file.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-1.png)

Then extracted it using the ``binwalk -e dolls.jpg``. Then `cd _dolls.jpg.extracted` followed by:

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-2.png)

Repeated the same steps several times and finally got the file `flag.txt` which contained the flag `picoCTF{336cf6d51c9d9774fd37196c1d7320ff}`

## 3. <mark>tunn3l v1s10n

#### Challenge description :

We found this `file`. Recover the flag.

[Challenge file](https://mercury.picoctf.net/static/d0129ad98ba9258ab59e7700a1b18c14/tunn3l_v1s10n)

#### Writeup :

I started checking the file type and it showed data. Then I tried to see its contents using cat but it ran some unknown binary and corrupted my terminal. Then I closed it and opened again and searched for metadata.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-11.png)

It showed that the file is actually bmp type which indicated that the file might have been corrupted. I also was unable to open it using my image viewer. So, I opened hexeditor and found the corrupted part.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-12.png)

Then rectified them using an actual bmp file. Now my image viewer opened it but it showed `notaflag{sorry}`. But it seemed that the full picture was not being seen due to height issues.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-13.png)

Then got the image height(306) from metadata and increased the height using hexeditor. Now the entire image was visible and we found the flag `picoCTF{qu1t3_a_v13w_2020}`. 

## 4. <mark>MacroHard WeakEdge

#### Challenge description :

I've hidden a flag in this file. Can you find it? 

[Challenge file](https://mercury.picoctf.net/static/9a7436948cc502e9cacf5bc84d2cccb5/Forensics%20is%20fun.pptm)

#### Writeup :

This challenge is only about searching here and there and finding the `hidden` file.

First I used `file` and `exiftool` to know the actual file type and they showed that it was `Microsoft PowerPoint`. Then as usual extracted the zip archive files using `binwalk -e Forensics\ is\ fun.pptm`. Then `cd _Forensics\ is\ fun.pptm.extracted` followed by-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-14.png)

Then opened the `[Content_Types].xml` file with sublime text but found nothing. Then one by one I checked all the directories and files and finally inside `ppt/slideMasters`, found the file `hidden`.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-15.png)

Now opened it using sublime text and removed all the spaces to get the base64 encoded string which after decoding gave the flag `picoCTF{D1d_u_kn0w_ppts_r_z1p5}`.

## 5. <mark>Enhance!

#### Challenge description :

Download this image file and find the flag.

[Challenge file](https://artifacts.picoctf.net/c/101/drawing.flag.svg)

#### Writeup :

I randomly tried some tools but they didn't work. But when I opened the file in `sublime text` and scrolled down, I noticed this-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-3.png)

This must have been the flag but not in the proper format, so I had to arrange it properly. So, again I used `strings drawing.flag.svg`. It showed the same thing but I had missed it first time 😅. 

Then I started arranging it-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-4.png)

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-5.png)

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-6.png)

Thus got the flag `picoCTF{3nh4nc3d_24374675}`

## 6. <mark>advanced-potion-making

#### Challenge description :

Ron just found his own copy of advanced potion making, but its been corrupted by some kind of spell. Help him recover it!

[Challenge file](https://artifacts.picoctf.net/picoMini+by+redpwn/Forensics/advanced-potion-making/advanced-potion-making)

#### Writeup :

First as usual I used `file advanced-potion-making` and it showed data. Then `exiftool advanced-potion-making` showed `unknown file type`. Next I used strings and it gave some clue:

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-17.png)

I wasn't familiar with these words, so I searched and found that IHDR is normally associated with png image files. This indicated that the magic bytes of the png file might have been corrupted. So, next I used `hexedit advanced-potion-making`.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-18.png)

Then changed the two bytes `42 11 -> 4E 47` and run `eog advanced-potion-making`. It showed invalid IHDR length.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-19.png)

Then I searched for IHDR header and found this image.

![image](https://i.sstatic.net/hcIIO.png)

And changed the IHDR length from `00 12 13 14` to `00 00 00 0D`. Then I was able to open the `advanced-potion-making` file and it rendered a red image. After that I used binwalk and other commands but nothing worked. Then I thought of changing the background colour by manipulating the bytes but wasn't able to do that correctly. And searching for a tool which could do the analysis on hidden messages inside images, I found [this](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.aperisolve.com/&ved=2ahUKEwiti5fLwMaGAxX2XGwGHQRmJ4IQFnoECBIQAQ&usg=AOvVaw0k8m6gI5IaJnVD1MJ5kAPW) online website. And after changing the extension of our file and uploading it in the website, we got the flag `picoCTF{w1z4rdry}`.

## 7. <mark>File types

#### Challenge description :

This file was found among some files marked confidential but my pdf reader cannot read it, maybe yours can.

[Challenge file](https://artifacts.picoctf.net/c/80/Flag.pdf)

#### Writeup :

`file Flag.pdf` showed that the file was `shell archive text`. `cat Flag.pdf` showed some comments which seemed to be beneficial-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-8.png)

Now the command `sh Flag.pdf` extracted a `flag` file which was of type `current ar archive`. Then `binwalk flag` showed that it contained a `bzip2 compressed` file.

Extracted it using `binwalk -e flag` followed by `cd _flag.extracted`. There was a file `64` which was gzip compressed. Then I had to decompress the file multiple times to get the flag.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-9.png)

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-10.png)

Similarly did these extractions: `lzip -> LZ4 -> LZMA -> lzop -> lzip -> XZ -> ASCII data` and finally got the encoded string which after decoding gave the flag `picoCTF{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_3c79c5ba}`

## 8. <mark>hideme

#### Challenge description :

Every file gets a flag.
The SOC analyst saw one image been sent back and forth between two people. They decided to investigate and found out that there was more than what meets the eye `here`.

[Challenge file](https://artifacts.picoctf.net/c/258/flag.png)

#### Writeup :

I started using binwalk.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-20.png)

And it seemed promising. Then extracted the files. Then `cd _flag.png.extracted`. 

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-21.png)

Inside the directory `secret` there is a file `flag.png`. Simply using `eog flag.png` showed the flag `picoCTF{Hiddinng_An_imag3_within_@n_ima9e_d55982e8}`. 

## 9. <mark>MSB

#### Challenge description :

This image passes LSB statistical analysis, but we can't help but think there must be something to the visual artifacts present in this image...

[Challenge file](https://artifacts.picoctf.net/c/301/Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png)

#### Writeup :

First I checked the file extension using `file`. It showed that the file is png image.Opened the blurred image. Then I used `binwalk` to extract the embedded files but they were of no use. Then `exiftool` and `zsteg` also didn't give much relavant information. Then I tried with a python script `decoder.py` to extract the hidden info using LSB analysis.

```py
from PIL import Image

# Open the image
img = Image.open("Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png")

# Load the pixel data
pixels = img.load()

# Initialize an empty string to store the binary message
bin_msg = ""

# Get the dimensions of the image
width, height = img.size

# Iterate over each pixel in the image
for y in range(height):
    for x in range(width):
        # Get the RGB components of the pixel
        r,g,b = pixels[x,y]

        # Extract the LSBs of the red component
        bin_msg += str(r&1)
        if len(bin_msg)%8 == 0:
            # Convert the binary message to text and print the hidden message
            print("".join(chr(int(bin_msg[i:i+8],2)) for i in range(0,len(bin_msg),8)))

```

Executed it using `python decoder.py | head -50`. But didn't get anything. Then tried with the green and blue colors but same result.

Next modified the script for MSB analysis as the description, challenge name and blurred image indicated that this time the MSBs might have been corrupted or modified.

```py
from PIL import Image

# Open the image
img = Image.open("Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png")

# Load the pixel data
pixels = img.load()

# Initialize an empty string to store the binary message
bin_msg = ""

# Get the dimensions of the image
width, height = img.size

# Iterate over each pixel in the image
for y in range(height):
    for x in range(width):
        # Get the RGB components of the pixel
        r, g, b = pixels[x, y]
        
        # Extract the MSBs (7th bit) of the red component
        bin_msg += str((r >> 7) & 1)

# After collecting all bits, convert the binary message to text
hidden_message = "".join(chr(int(bin_msg[i:i + 8], 2)) for i in range(0, len(bin_msg), 8))

# Print the hidden message
print(hidden_message)

```

It also didn't work. Next I used `Aperi solve` but this time it was unable to find something. I even downloaded `openstego` but it showed -

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-22.png)

Then I searched for `MSB steganography decoder online` and first found [this](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://stylesuxx.github.io/steganography/&ved=2ahUKEwiz9p6FkcmGAxXbj68BHWSyF3YQFnoECBQQAQ&usg=AOvVaw3BoM9agDA-VTpFMEwSX5LG) website. It also didn't work. Then looked into [this](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://medium.com/ctf-writeups/stegonline-a-new-steganography-tool-b4eddb8f8f57&ved=2ahUKEwiz9p6FkcmGAxXbj68BHWSyF3YQFnoECBgQAQ&usg=AOvVaw1Kqu9j_xk7ofDmsC4QSqTd) second link and 
learned about stegonline. In this tool we can modify any bits according to our choice. So I went to [stegonline](https://stegonline.georgeom.net/) and selected `Extract files/data`. There I marked the R,G,B boxes for the 7th bit and it extracted the data. Then I opened the downloaded file in sublime text and searched for the string `picoCTF` and found the flag `picoCTF{15_y0ur_que57_qu1x071c_0r_h3r01c_3a219174}`.



## 10. <mark>extensions

#### Challenge description :

This is a really weird text file `TXT`? Can you find the flag?

[Challenge file](https://jupiter.challenges.picoctf.org/static/e7e5d188621ee705ceeb0452525412ef/flag.txt)

#### Writeup :

The file was named `flag.txt`. But I didn't trust it. So, I used `file flag.txt` and it showed that actually it is a PNG image data. So, I used `eog flag.txt` and got the flag `picoCTF{now_you_know_about_extensions}`.


---

# OSINT

---

## 1. TryHackMe

---

### <mark>Task 1

Just write `Let's go`.

### <mark>Task 2

[Challenge file](https://raw.githubusercontent.com/OsintDojo/public/3f178408909bc1aae7ea2f51126984a8813b0901/sakurapwnedletter.svg)

#### Writeup :

Simply using exiftool on the file, we get the metadata. 

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-23.png)

And the username of the attacker is `SakuraSnowAngelAiko`.

### <mark>Task 3

#### Writeup :

Now inside the directory, `/sherlock/sherlock`, we run `python3 sherlock.py SakuraSnowAngelAiko` to get the other websites where the username is used. I started going through the links and the [github](https://www.github.com/SakuraSnowAngelAiko) link showed some relavant details. I started searching the repositories and in the `PGP` repository, I found the `PGP public key` of the attacker. Then from chatGPT I got to know how to get the email address from the key. So, I used `nano demo.asc` and pasted the public PGP key there. Next used the command-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-24.png)

And got the email address `SakuraSnowAngel83@protonmail.com`.

Next I found the full real name of the attacker i.e. `Aiko Abe` from the second [image](https://raw.githubusercontent.com/OsintDojo/public/main/taunt.png) that was provided in the room.

### <mark>Task 4

#### Writeup :

Next in the `ETH` repository, I found a commit in which there was information about the attacker's cryptocurrency wallet. There found his wallet address `0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef` and the mining pool `Ethermine`.

Next I google searched for the wallet address and found that it was `Ethereum`. 

Also I found the link [Etherscan.io](https://www.google.co.in/url?sa=t&source=web&rct=j&opi=89978449&url=https://etherscan.io/address/0xa102397dbeebefd8cd2f73a89122fcdb53abb6ef&ved=2ahUKEwiyk9ak5suGAxWGs1YBHRc2C7AQnPYJegQICBAC&usg=AOvVaw22SxwJxl0cRKljvvKmYvYJ) which contained the information about his transactions. There went for `view all transactions` and found `Tether` at the bottom.

### <mark>Task 5

[Challenge file](https://raw.githubusercontent.com/OsintDojo/public/main/taunt.png)

#### Writeup :

In twitter I searched for `@AikoAbe3` and found his account. His twitter handle was `SakuraLoverAiko`. 

Next I downloaded [this](https://raw.githubusercontent.com/OsintDojo/public/main/deeppaste.png) file given in the hint option and got the URL `deepv2w7p33xa4pwxzwi2ps4j62gfxpyp44ezjbmpttxz3owlsp4ljid.onion` and appended `http://` to submit the task. 

Then after searching a while for a site that could give information about BSSID, in chatGPT I found this [Wigle.net](https://wigle.net/) site. Then as instructed in the hints, I first registered an account there and used the advanced search. Then I put the SSID `DK1F-G` which I found from the previous screenshot and hit Query.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-25.png)

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-26.png)

And thus got the BSSID `84:af:ec:34:fc:f8`.

### <mark>Task 6

#### Writeup :

Got this [image](https://pbs.twimg.com/media/Esh-uTvUcAc-sXC?format=jpg&name=large) and used google lens. But found nothing relavant but only cherries. Then used other sites but nothing. Then started cropping randomly and in some trial it worked. It highlighted the monument far behind and it was `Washington Monument`. Then it was very simple to search for the closest airport and it is `DCA`.

Next I searched the layover [image](https://pbs.twimg.com/media/EsiM12KVoAEhAsI?format=png&name=small) and this time highlighted the SKYRAX award and found that it was Haneda Airport that is `HND`.

Now its turn for the map [image](https://pbs.twimg.com/media/EsiNRuRU0AEH32u?format=jpg&name=medium). I cropped the lake part and at a particular instant it showed the lake name `Lake Inawashiro`.

Now tried with the map to somehow find the home city but nothing worked. Then after watching the hint, I got that the wifi details may help this time and went back to [Wigle.net](https://wigle.net/). There put the SSID and BSSID, hit query and clicked in the map botton.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-28.png)

And it pointed to the city `Hirosaki`.


---

## 2. OSINT Exercises

---

### <mark>#006

[Challenge file](https://gralhix.com/wp-content/uploads/2023/08/osintexercise006.webp)


#### Challenge description :

On January 19, 2023, a journalist with almost 140k followers on Twitter shared an image of a destroyed vehicle amidst a large cloud of smoke and fire. The tweet said: “BREAKING: TTP carried out a suicide attack on a police post in Khyber city of Pakistan that killed three Pakistani police officers.“

The photo is not of the event described by the journalist.
a) Verify the statement above.


#### Writeup :

Simply we reverse search for the image and in `Tineye` we find [this](https://alamy-ltd.ewrvdi.net/c/77643/748811/10905?u=https%3A%2F%2Fwww.alamy.com%2Fwaziriyaautobombeirak-image574866988.html) site. Scrolling a little down we find this.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-29.png)

The image data was taken in 28 August 2006 and the date in the tweet is Jan 19,2023 which is definitely false.

Hence, the statement is true.

### <mark> #004

[Challenge file](https://gralhix.com/wp-content/uploads/2023/08/osint-exercise-004-big-picture.jpg)

#### Challenge description :

This is a photo of a resort located on an island.
a) What is the name of the resort?
b) What are the coordinates of the island?
c) In which cardinal direction was the camera facing when the photo was taken?

#### Writeup :

Again we use all the reverse searching tools and this time only google search has got some relavant links. We search through the [facebook](https://www.facebook.com/oanresort/) link.

We find that the resort name is `Oan resort`. Then we browse in the official [website](https://l.facebook.com/l.php?u=https%3A%2F%2Foanresort.wixsite.com%2Fchuuk&h=AT036rqrxEYo3d36cVAz4mF0xAmAZVamaicacuasT1mPQIxN3WzxrIb1OjS7w1bSxeztuTXoh2_-aatTUfk8-zgMBoUPS1GmMI8OTdlVMlv2BoJcU4QzgWRSm9EooDXv71U4POC-AUU6agNd8DobtI6oaOWFBjRGYtqvxlk8_Xk) of the resort found in the intro. There I watched the videos and got the map of the resort in the contact part. Then I searched for the resort in google map and got its coordinate `7.36276N 151.75651E`. Using google map I wasn't perfectly able to answer the last part. Then after watching the video, I came to know about `Google Earth Pro` and after using it got that the cardinal direction of the camera was `North-West`.


### <mark> #003

[Challenge file](https://gralhix.com/wp-content/uploads/2023/08/osint-exercise-003-picture.jpg)


#### Challenge description :

In April 2017 Mohamed Abdullahi Farmaajo, the then president of Somalia, visited Turkey. A news agency published a photo where he was seen shaking hands with Recep Tayyip Erdoğan, the country’s president. The article did not disclose where the photo was taken. Find out the name and coordinates of the location seen below.


#### Writeup :

The challenge description itself had many informations to search for. When I searched for them in chatGPT, it gave me two options. First was the `Presidential Complex in Ankara`. Then I searched it in google and found the exact same location. Then in [Wikipedia](https://en.wikipedia.org/wiki/Presidential_Complex_%28Turkey%29) found its coordinates `39.9308˚N 32.7989˚E`.


### <mark> #014

[Challenge video](https://youtu.be/myTG1LpMN7g)

#### Challenge description :

The video below was recorded during an earthquake.

a) What was the magnitude of this earthquake?
b) What are the coordinates of where the camera was likely located in order to record this scene?

#### Writeup :

First I didn't know any tool to reverse search a video. So, I took this screetshot and tried to analyse it.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-30.png)

Uploaded this image in google lens and after searching a bit I clicked in ***image source*** and there I found a number of youtube videos pointing that the incident happened in ***Romania*** and had an magnitude of ***5.8***. Also found [this](https://www.youtube.com/watch?v=lvGpouFqmJ0) video which is the same one we were given in the exercise. Also ***"Cutremur Chisinau"*** in the video is written in Romanian and means ***Chisinau earthquake***. Then I searched for Chisinau in google map and it was in Moldova, a neighbour country of Romania. 

Next I had to find the exact location of the footage area. I searched in google map but could not find it. I also tried cropping at different parts of the screenshot but no result. Then I watched the video and realized how to deal with such problems. After narrowing our search zone by searching for all the car dealers in that area and then trying to locate with the roads and buildings nearby helped us in this case. And finally got the coordinates of the camera ***47.017555N 28.85275E***.


### <mark> #026

[Challenge files](https://gralhix.com/wp-content/uploads/2024/04/osintexercise026.zip)

#### Challenge description :

The image below shows the contents of a zip file. Inside you will find a 31-second video recorded during a train ride, and four photos of undisclosed locations. They were all taken by the same individual in February 2024. Despite having no useful metadata, they still contain enough information to track down this person’s movements.
Your task is to determine:

a) At which train stations did the person board and alight?

#### Writeup :

