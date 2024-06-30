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



## 13. <mark>Java Script Kiddie 2</mark>

### Challenge description :

The image link appears broken... twice as badly... https://jupiter.challenges.picoctf.org/problem/38421 or http://jupiter.challenges.picoctf.org:38421

### Writeup :

