# Writeups for CSOC-week 3

---

# Web Exploitation

---

## 1. <mark>Web Gauntlet</mark>

### Challenge description :

Can you beat the filters? Log in as admin

### Challenge links :

[http://jupiter.challenges.picoctf.org:9683/](http://jupiter.challenges.picoctf.org:9683/)

[http://jupiter.challenges.picoctf.org:9683/filter.php](http://jupiter.challenges.picoctf.org:9683/filter.php)

### Writeup :

This challenge has 5 rounds and there are different filters used in different rounds which means that we can't use the given filters to login. Also we have to login as `admin`.

##### Round 1-

For the first round the filter is `or` that is we can't use **or**. From the page [SQL injection cheat sheet github](https://github.com/payloadbox/sql-injection-payload-list), we can get the list of payloads that can be injected in the SQL injectable site. For this round we can give the username as `admin';` and a random password. The character `;` simply terminates the line. So the term `SELECT * FROM users WHERE username='admin';` will be evaluated which is **true**. So, we will pass this level.

##### Round 2-

Filters: `or and like = --`

The good news is that `;` will not be filtered and we can login in the same way by the username `admin';` and any password.

##### Round 3-

Filters: `or and = like > < --`

Same way, username=`admin';`

##### Round 4-

Filters: `or and like = -- admin`

Now we can't use **admin**. After searching a bit, I found the query `||` which concatenates two strings. Though we can't use `admin` directly, we can break it into two parts and  concatenate them. So, now I used `ad'||'min';` as username and it worked properly.

##### Round 5-

Filters: `or and = like -- union admin`

We have no issues with `ad'||'min';` and I used it again to pass the final level. Now the **filter.php** showed the source code and the flag **picoCTF{y0u_m4d3_1t_275cea1159781d5b3ef3f57e70be664a}**.

## 2. <mark>Web Gauntlet 2</mark>

### Challenge description :

This website looks familiar... Log in as admin

### Challenge links :

Site: [http://mercury.picoctf.net:57359/](http://mercury.picoctf.net:57359/)

Filter: [http://mercury.picoctf.net:57359/filter.php](http://mercury.picoctf.net:57359/filter.php)

### Writeup :

The filters are `or and true false union like = > < ; -- /* */ admin`.

For the username section, we can simply concatenate `ad` and `min` but the problem this time is that all the options to comment out the remaining part will be filtered. So, first I tried with the username `ad'||'min'||'%00` as `%00` represents a null byte but it didn't work. Also tried to comment out using `#`, by using `\0` but nothing worked. Then used several techniques before getting introduced to [this](https://www.tutorialspoint.com/sqlite/sqlite_operators.htm) site and found the `IS` and `IS NOT` operators which work similar to `=` and `!=` respectively. Then tried with username=`ad'||'min` and password=`1' IS '1` but it didn't work. Then changed the password to `1' IS NOT '2` and surprisingly it cleared the level and I got the flag **picoCTF{0n3_m0r3_t1m3_d5a91d8c2ae4ce567c2e8b8453305565}** in the filter.php.

## 3. <mark>Web Gauntlet 3</mark>

### Challenge description :

Last time, I promise! Only 25 characters this time. Log in as admin

### Challenge links :

Site: [http://mercury.picoctf.net:24143/](http://mercury.picoctf.net:24143/)

Filter: [http://mercury.picoctf.net:24143/filter.php](http://mercury.picoctf.net:24143/filter.php)

### Writeup :

Filters: `or and true false union like = > < ; -- /* */ admin`

I think that the previous method would also work this time. So, used the username=`ad'||'min` and the password=`1' IS NOT '2` and easily got the flag **picoCTF{k3ep_1t_sh0rt_fc8788aa1604881093434ba00ba5b9cd}**.

## 4. <mark>Irish-Name-Repo 1</mark>

### Challenge description :

There is a website running at https://jupiter.challenges.picoctf.org/problem/50009/ (link) or http://jupiter.challenges.picoctf.org:50009. Do you think you can log us in? Try to see if you can login!

### Writeup :

The given link leads us to the problem page. In the top left corner, we have the menu button(≡) that contains the *Admin Login* option.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-37.png)

Clicking on that opens the login page for the admin. I simply passed `admin';` as the username.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-38.png)

Hit enter and got the flag **picoCTF{s0m3_SQL_fb3fe2ad}**. By the way it wasn't necessary to fill the password .

## 5. <mark>Irish-Name-Repo 2</mark>

### Challenge description :

There is a website running at https://jupiter.challenges.picoctf.org/problem/53751/ (link). Someone has bypassed the login before, and now it's being strengthened. Try to see if you can still login! or http://jupiter.challenges.picoctf.org:53751

### Writeup :

In the exact way, we go to the *Admin Login* page and give the username `admin'--`. Tried something different this time and that also worked and I got the flag **picoCTF{m0R3_SQL_plz_c34df170}**

## 6. <mark>Irish-Name-Repo 3</mark>

### Challenge description :

There is a secure website running at https://jupiter.challenges.picoctf.org/problem/40742/ (link) or http://jupiter.challenges.picoctf.org:40742. Try to see if you can login as admin!

### Writeup :

This time the login page only had the password option.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-39.png)

First, I checked the output by entering a random string and it showed `Login failed.` Then, my approach was to proceed in the same way as I tried for the 2nd and 3rd challenge for the password option. So, I started with `1' IS 1'` but it showed **internal server error**. Similar problem with `1' IS NOT '2`. So, next I tried `1'='1` but it showed `Login failed.` Finally I typed `1'!='2` and this time got the flag **picoCTF{3v3n_m0r3_SQL_4424e7af}**.

## 7. <mark>JaWT Scratchpad</mark>

### Challenge description :

Check the admin scratchpad! https://jupiter.challenges.picoctf.org/problem/58210/ or http://jupiter.challenges.picoctf.org:58210

### Writeup :

First of all I went to the login page and registered with my name `ankit`. So it opened the scratchpad. Then I logged out and tried to login with `admin` but it wasn't allowed.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-51.png)

In the login page, there were two links: [JWT](https://jwt.io/) and [John](https://github.com/magnumripper/JohnTheRipper). So, they must be linked with the flag in some manner and we have to discover that. The former link directed us to the website `jwt.io`.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-53.png)

In the encoded part, it told to **paste a token** and in the decoded part it told to **edit the payload and secret**. At first, I could not relate this and tried several things.

Then, in the hint section of the challenge, there was a mention of `cookie`. So, again I logged in as `ankit` and inspected the cookie stored. It was `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYW5raXQifQ.jurt8WnyXXYF0Z8sh5V1dn_Q2ev5Kn-BP-mY1wMtXBk` and looked quite similar to the token in the jwt.io site. So, I pasted it in the encoded part. The only change in the decoded part was the payload and it showed `"user": "ankit"`. Then I replaced `ankit` with `admin`, copied the new token and pasted into the cookie. But reloading the page showed error. After several trials, I realized that only changing the payload isn't going to do anything. In addition I have to change the **secret** also. And since I wasn't doing that, I got error from the site.

But I didn't know the secret message. So, I must find that. Next I thought how to use `JohnTheRipper` as it was mentioned. After thinking some time, I realized that the token was a hash infact and `JohnTheRipper` needs a hash to crack the password. So, why shouldn't I try to crack the `secret` using the token and john?

Next, saved the contents of the token in a file `jwt_hash` and did this-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-40.png)

And got the secret password `ilovepico`. Then typed `ilovepico` in place of secret and `"user": "admin"`.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-41.png)

And pasted the new token in the cookie. Then reloading the page rendered the flag **picoCTF{jawt_was_just_what_you_thought_44c752f5}**

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-42.png)

## 8. <mark>Secrets</mark>

### Challenge description :

We have several pages hidden. Can you find the one with the flag?
The website is running here.

### [Challenge link](http://saturn.picoctf.net:58494/)

### Writeup :

I went through the link. The webpage doesn't seem to have something crazy. So, I opened the devtools and the `elements` section had a mention of a `secret` folder.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-43.png)

Inside the `secret` folder, I found the folder `hidden` and inside hidden there was a `superhidden` folder. I went through that and in the devtools found the flag **picoCTF{succ3ss_@h3n1c@10n_39849bcf}**

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-44.png)

## 9. <mark>Client-side-again</mark>

### Challenge description :

Can you break into this super secure portal? https://jupiter.challenges.picoctf.org/problem/6353/ (link) or http://jupiter.challenges.picoctf.org:6353

### Writeup :

I went to the login page and tried with some SQL injections but they didn't work. Then I opened the devtools and looked into this. In the elements section, I found this script-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-45.png)

In the second line of the script(inside square brackets), I found `picoCTF{` and some other strings containing underscore(_) and closing brace(}). So, by intuition, I arranged 4 strings to make the flag **picoCTF{not_this_again_50a029}** and after submitting got confirmed that it was correct.

## 10. <mark>Who are you?</mark>

### Challenge description :

Let me in. Let me iiiiiiinnnnnnnnnnnnnnnnnnnn

http://mercury.picoctf.net:38322/

### Writeup :

I similarly tried by searching in the source page and devtools but found nothing. Then opened burpsuite to intercept the request but could not figure out how to proceed exactly. After trying a lot, I had to look up to some writeups and understood what was happenning. Got to know about different headers.

Now, first I changed the `User-Agent` to `PicoBrowser` as we can go further only if we are in that browser.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-50.png)

Next, the response told that it doesn't trust users from another site. So, I searched for how to know from which site an user is coming and found [this](https://stackoverflow.com/questions/1354597/how-to-determine-where-a-user-came-from-to-my-site#:~:text=sign%20up%20for%20google%20analytics,checking%20the%20http%20referer%20header.) stack overflow page. The `Referer` header does this. So, I added the header `Referer`.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-55.png)

Then sending the request showed another response that this site worked only in 2018. So, next I had to add the `Date` header.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-56.png)

The next response was that it doesn't trust users who can be tracked. So, I searched for it and found [this](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/DNT) DNT site. Scrolled a little bit and found this-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-57.png)

So, I added the header `DNT: 1`. It worked and showed a new message in the response that the website is only for people from Sweden. So, I had to look around how can I do that and found that it could be done using the IP address. So, I searched for the appropriate header and got this-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-58.png)

And found the IP address of sweden from [this](https://lite.ip2location.com/sweden-ip-address-ranges?lang=en_US) site and grabbed the very first one `102.177.146.0`. This worked and got the new message that I had to speak swedish. But the `Accept-Language` in my request was `en-US`. Then from [this](https://github.com/fastlane/boarding/issues/69) site found the swedish accept-language that is `sv-SE`. Replaced it in my request-

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-54.png)

And got the flag **picoCTF{http_h34d3rs_v3ry_c0Ol_much_w0w_79e451a7}**

## 11. <mark>IntroToBurp</mark>

### Challenge description :

Try here to find the flag

### [Challenge link](http://titan.picoctf.net:51546/)

### Writeup :

Went through the link to the registration page. Without registering, first I opened burpsuite and intercepted the connection, as instructed in the hint section.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-47.png)

Then I started mangling the request in burpsuite but after trying a bit, got nothing.

Next, I registered with random informations and hit submit. A new request was intercepted by burpsuite.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-46.png)

Now, mangled the token, username, password and other things but they also didn't work. So, I forwarded the request in burp and a new page to enter OTP got opened. I submitted a random otp and again intercepted in burp.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-48.png)

And when I deleted the `p` from `otp` and sent the request again, got the flag **picoCTF{#0TP_Bypvss_SuCc3$S_e1eb16ed}** in the response.

![Alt text](https://github.com/tig-paul/CSOC-2024/blob/main/Writeup_files/image-49.png)

## 12. <mark>Java Script Kiddie</mark>

### Challenge description :

The image link appears broken... https://jupiter.challenges.picoctf.org/problem/42101 or http://jupiter.challenges.picoctf.org:42101

### Writeup :

The link directed me to the site. It had a submit box and submit option. I entered random string but it showed a broken image as it was told in the challenge description. Then I looked through the source page and in the head section found this script-

```js
var bytes = [];
$.get("bytes", function(resp) {
  bytes = Array.from(resp.split(" "), x => Number(x));
});

function assemble_png(u_in){
  var LEN = 16;
  var key = "0000000000000000";
  var shifter;
  if(u_in.length == LEN){
    key = u_in;
  }
  var result = [];
  for(var i = 0; i < LEN; i++){
    shifter = key.charCodeAt(i) - 48;
    for(var j = 0; j < (bytes.length / LEN); j ++){
      result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
    }
  }
  while(result[result.length-1] == 0){
    result = result.slice(0,result.length-1);
  }
  document.getElementById("Area").src = "data:image/png;base64," + btoa(String.fromCharCode.apply(null, new Uint8Array(result)));
  return false;
}
```

In the description, it was written that the broken image was just a javascript problem. So, I decided to understand the script first and then proceed.

### Code Explanation :

First it declares an array named bytes and then sends a get request to `bytes`. Now let see what is inside bytes. It contains some random decimal numbers-

> 156 255 80 255 117 10 239 248 152 253 120 232 36 127 116 255 151 235 25 172 215 0 56 102 219 174 30 15 36 188 93 90 249 36 32 45 123 73 191 151 236 241 151 68 144 250 157 130 1 180 20 85 213 2 157 248 68 255 250 13 60 66 249 82 187 157 29 222 29 30 0 252 126 251 95 0 174 72 194 108 29 101 70 21 121 40 26 132 73 119 254 237 73 192 96 219 137 80 89 71 0 145 1 152 0 69 254 71 0 65 68 35 0 0 119 114 13 222 68 119 1 0 78 40 155 111 95 90 164 0 26 2 0 245 186 0 84 0 0 233 145 46 110 49 48 16 78 223 135 64 197 10 0 120 0 243 252 62 144 188 21 61 1 110 148 208 22 114 160 31 156 17 45 59 72 237 74 218 0 8 32 123 136 65 179 150 32 56 206 43 240 9 156 225 69 54 226 158 106 148 62 48 1 232 173 0 239 248 243 206 82 255 241 252 56 55 152 132 108 181 78 254 175 251 60 183 38 231 63 123 204 48 43 13 131 4 113 75 243 215 32 200 144 195 29 233 196 63 3 190 139 207 89 28 107 159 185 101 59 120 121 12 245 116 64 96 250 187 241 234 231 207 213 239 119 191 233 71 205 127 144 40 251 253 173 186 246 10 227 252 202 242 163 74 237 33 75 49 205 74 154 165 126 231 30 231 232 199 118 65 211 98 204 7 250 244 141 155 243 123 82 137 252 35 183 201 132 91 252 37 244 56 188 86 125 103 216 248 215 146 144 149 21 164 233 219 127 127 207 208 30 154 111 203 63 127 141 231 146 5 20 4 81 239 38 36 19 191 63 61 183 223 215 205 210 239 168 135 148 201 39 248 212 191 160 151 116 19 150 99 249 141 111 188 0 225 193 61 73 140 160 56 23 53 48 5 99 100 175 250 125 151 253 12 150 85 41 72 206 97 52 79 88 196 130 26 157 254 185 181 42 146 217 255 24 125 155 88 111 116 167 62 238 36 52 95 57 54 126 233 184 143 46 183 234 73 183 108 163 228 218 233 129 44 169 191 74 0 30 126 245 10 249 245 241 65 191 245 73 209 50 140 26 72 132 223 181 204 200 123 185 186 183 218 175 228 249 75 180 91 229 252 193 203 187 253 52 166 28 117 119 13 238 134 74 227 127 71 251 237 50 191 61 76 230 90 241 178 221 233 202 254 211 228 156 60 202 241 71 49 24 90 187 3 245 247 159 124 157 250 227 18 150 50 49 101 86 235 162 234 57 124 108 116 245 226 190 28 43 129 220 86 245 85 107 38 215 223 119 242 72 140 213 103 209 194 70 30 96 111 204 128 234 55 184 247 205 49 227 5 220 101 80 171 155 217 87 33 26 173 127 187 128 253 215 111 203 54 210 243 29 237 148 204 235 202 131 191 191 211 157 54 147 104 188 87 4 251 25 17 185 219 247 124 135 228 176 223 135 196 157 130 215 206 124 122 136 248 28 23 175 56 104 209 253 47 161 236 61 252 147 140 86 102 185 82 110 231 91 251 245 216 243 254 236 176 127 134 31 135 152 251 90 0 216 127 102 56 99 56 64 204 61 95

Next it takes the numbers from `bytes`, splits them and stores them in the list **bytes**. By the way, the length of bytes is **704**. Then there is a function `assemble_png` which takes an user input(u_in). Then it declares the variables LEN, key, shifter. If length of u_in is equal to 16, then it updates the value of key to be u_in. Next it declares a result array. Then in each iteration of the for loop it converts the i-th string element of key into integer and stores it in shifter. Then it runs an inner for loop in which it takes a random element from the bytes array and stores it in a random index of the result array using the shifter, LEN and loop variables . Basically it scrambles the elements of the bytes array and stores them in result. Then in the next while loop, it deletes the zeroes at the end of the result array if any. At last, using the result array, it converts the binary data into base64 and creates the png image file.

## 13. <mark>Java Script Kiddie 2</mark>

### Challenge description :

The image link appears broken... twice as badly... https://jupiter.challenges.picoctf.org/problem/38421 or http://jupiter.challenges.picoctf.org:38421

### Writeup :

