# AfricaCyberfest CTF 2024 

![ctf-landing-page](images/ctf_landing_page.png)

Hi 👋,

I had the pleasure of participating in the AfricaCyberFest 2024 CTF with my team, BOTscope, under the alias Lan0srespii_Legacies. In this repository, I'll be sharing detailed write-ups for some of the challenges I managed to solve during the competition.

<h3>Challenges</h3>

## General
- Do you read
- Say Hello
- Do you read 2
  
## Cryptography
- ByteOps

## Web
- Troll

## Reverse Engineering
- Sore
- Finding Nulock

## Digital Forensics
-  Whispers in the Wires
  
## Misc
-  Hip Hip HIp!


Let try to solve this 😎


### Do you read
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/7959b41a-de7b-4146-9201-ee1f00422abe)

It's clearly referring to the main page of the site, so I navigated there, inspected the page source, and found the flag.
![image](images/do_you_read.png)

```
Flag: ACTF{dont_skip_cutscenes}
```

### Say Hello
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/be74af8b-ed43-46af-a222-6c28f729d021)

Since I had been following most of the accounts already, I followed the new ones and then submitted. `Yes` :)

```
Flag: Yes
```

### Do you read 2
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/191d940a-9684-4c31-bdbb-f9d80926837b)

Just submit that 

```
Flag: actf{i_did_not_skip_this_cutscene}
```


### Troll
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/813b37d2-c052-41b1-9409-a985da23ed3d)

Navigating to the provided URL didn't display any content.
![image](images/trolls.png)

Viewing page source reveals nothing also
![image](images/trolls_viewsource.png)


To ensure the security and thorough assessment of the target website, I utilized the "Discover Hidden Directories and Files" tool provided by Pentest-Tools.com. This tool is designed to uncover directories and pages that are not easily visible through standard navigation or indexing.

![image](images/trolls2.png)

![image](images/trolls3.png)

After searching for hidden directories, I found this site, 
![image](images/trolls4.png)

After navigating to the robots.txt page, I found that the content included the line "/flagflagflag.txt," indicating that a flag might be related to this file. Additionally, I downloaded the robots.txt file for further analysis.
![image](images/trolls5.png)

I opened the robots.txt file with Notepad and found a word matching the pattern "actf
Boom! I found the flag. 
![image](images/trolls6.png)

```
Flag: aCtF{robotTxt_and_strings_as_requested}
```


### Finding nulock 
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/6d7d2808-87fc-427a-adf1-14d8a71ddec2)

Basically, after identifying the file as a Java APK using the file command on my Kali Linux environment and confirming it was indeed an APK, I attempted to download it on a Windows environment. However, I received a virus warning during the download attempt.
![image](images/newchallapk.png)

So, I adjusted my settings to allow the file to be downloaded. Then, I used an online [decompiler](https://www.decompiler.com/) to analyze the APK file.

![image](images/decomp.png)

Upon decompiling, we could see resources and identified a Metasploit stager within the file
![image](images/decomp2.png)

I went into the resource folder and downloaded the classes.dex file because I suspected it might contain crucial information or code. The classes.dex file is a compiled file in Android applications that contains executable code and resources. Since APK files are essentially Android application packages, it was reasonable to suspect that the classes.dex file might contain important functionality or even potential vulnerabilities, considering the suspicious nature of the APK file and its association with Metasploit.
![image](images/decomp3.png)

![image](images/decomp4.png)


After downloading the classes.dex file, I used Visual Studio Code to view its contents. Given the suspicion surrounding the APK file and the presence of a Metasploit stager, I searched within the classes.dex file for the format "ACTF{". Boom! I found the flag.

![image](images/decomp5vsc.png)

```
Flag: ACTF{Dynamic_Analysis_h0s7_R3v3al5}
```

### Hip Hip HIp!
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/0e5c10bb-5696-4341-85f8-c2ff7aff617c)

Just submit that :)

```
Flag: ACTF{Happy_Birthday!_Lytes}
```

At the end of the CTF prequalification, my team secured the 4th position. In the final, we maintained our 4th place. However, I felt disappointed as I managed to solve the trickier challenges only after the CTF concluded. Nonetheless, considering this was my first official CTF, I still see it as a significant achievement.
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/d27fbef6-1018-4298-a4b0-9a8fd5da877a)

Challenges Solved After CTF Finals:

After the CTF finals concluded, I managed to solve some of the trickier challenges.

# fun???
![image](images/fun.png)
The discovery revolves around Unicode steganography, particularly with zero-width characters

When you inspect element you’ll see this
![image](images/zerowidth.png)



















