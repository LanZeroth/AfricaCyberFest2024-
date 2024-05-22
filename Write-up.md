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





-- He delivered



Now let's get to it

Going to the attached url doesn't show anything
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

This was the first reverse engineering challenge, and we were given an apk file
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/879edf55-dc4a-4cd5-8def-d02c99aa7e90)

First thing I tried was to unzip the file, grep for the flag, convert the dex files to jar using `dex2jar`, decompile the converted dex file using `jd-gui`

Doing that I didn't really get anything and `jd-gui` decompilation was a bit off

So I tried using an online [decompiler](https://www.decompiler.com/)
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/f27807bc-1b9d-4e35-a29c-171ecd8bda4d)

Next i downloaded the zip file
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/e1d2da91-b134-4e92-8595-7f5f5890b7a0)

Unzipping it and opening in vscode should give this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/0546674f-029b-4b31-8f79-5af3e04c2914)

Looking through the classes i saw `Payload.java` which looked interesting

Viewing it shows this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/c00628aa-dd8a-4be1-b408-27c9ba2a6e08)

We can right away tell we should decode that

I just copied and paste that array to python interpreter then converted them to `chr`
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/6c7ef4ee-319b-439e-9c1a-2f6ccf069e71)

That gives error and that's because it isn't in the printable range for example `-5` isn't a printable value

To fix this we need to `AND` it with `255 == 0xff` which is equivalent to `% 256` and that would make each value there in the printable range
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/b7423d26-bc55-47aa-8305-6756837dd86b)

With that we get the flag

```
Flag: ACTF{Dynamic_Analysis_h0s7_R3v3al5}
```

### Sore
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/d984a085-ec6b-4941-9aba-e33f9ac2aa9d)

The second and last reverse engineering challenge

We are given an executable file
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/5d6a3fa3-f782-4524-9779-14b2aa55e964)

The description states that it's a malware yet silly me still ran it 💀

When I ran it, the program asks for input
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/b3526d2b-d8e4-4072-9b1f-ed772c7d80e5)

After we give it input then it would log out from the current session

That's why i am running it in gdb so that it won't logout yet

One important thing is this:

```
Input the flag. I'll let you know if it's correct
```

The program claims it will let us know if our provided input is right? That means it's going to be giving us an oracle which would basically allow us know if each character of the given input is right or wrong therefore giving us the primitive to brute force the flag

But before we think of brute forcing I needed a way to prevent it from logging out

I threw the binary into Ghidra to do some reversing or so I thought?

Unfortunately the binary is a rust compiled binary and I am not familiar with rust so I had some issue with figuring out what it does

But my goal was to figure out the instruction which would call program to logout our session and thereby patching it

Starting from the entry function I got this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/23910358-607c-48f0-9196-38a4edf7e3ae)

The main function is the first parameter passed to `__libc_start_main` which is `FUN_0012bc90`

Clicking on it shows this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/9e243555-5daa-49ca-bbd3-d6086776ec73)

```c
void FUN_0012bc90(int param_1,undefined8 param_2)

{
  code *local_8;
  
  local_8 = FUN_0012b890;
  FUN_002eb380(&local_8,&PTR_FUN_00398048,(long)param_1,param_2,0);
  return;
}
```

Variable `local_8` is a function pointer to `FUN_0012b890` 

Clicking on that shows this, which seems to be the function that handles the input validation and presumably the logout function?
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/6284df13-42c8-4dde-9227-d6af6224c464)
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/113d03b0-3b29-4943-b0f1-6564116a0459)
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/22ff1f66-8298-4609-aa79-ddd32651c8f3)

Since it's going to logout after we give it input i decided to start clicking on functions which is at the end

```c
LAB_0012baba:
    local_90 = &PTR_s_Wrong!_Input_the_flag._I'll_let_y_00398098;
    local_88 = 1;
    local_80 = 
    "Wrong!\nInput the flag. I\'ll let you know if it\'s correct\nFailed to read inputmain.rsYou\'re  partially right\n"
    ;
    local_78 = ZEXT816(0);
    FUN_002eee30(&local_90);
    local_90 = (undefined **)thunk_FUN_00167990();
    if (local_90 != (undefined **)0x0) {
      FUN_0012b750(&local_90);
    }
    goto LAB_0012bb04;
  }
  goto LAB_0012ba50;
}

```

On clicking funtion `thunk_FUN_00167990`, i saw that it's the function that handles the logout
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/2067c8e3-d4db-4a28-9f18-f957f8c8bcd0)

The function names are stripped which makes assumption hard since I don't know rust but we can tell because of this:

```c
cVar6 = FUN_001671e0("org.gnome.SessionManager/org/gnome/SessionManagerorg.kde.ksmserver/KSMServer org.kde.KSMServerInterfacelogoutorg.xfce.SessionManager/org/xfce/SessionManagerorg.freedesktop.log in1/org/freedesktop/login1org.freedesktop.login1.ManagerLogout"
```

The logout string there should just make you guess you are at the right track (don't quote me) 👀

Now that we figured that we need to patch the opcode
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/2d9f8845-6e10-457a-aa53-eb2eccf8240d)

```
        0012baea ff 15 58        CALL       qword ptr [->thunk_FUN_00167990]                 undefined thunk_FUN_00167990()
                 d3 27 00                                                                    = 0012de50
```

So we will change `0xff1558d32700` to `0x909090909090`

With that instead of the program calling that function it will just do nothing (nop -> no operation)

Here's the [script](https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/cyberfest24/scripts/sore/patch.py) I wrote to patch it

```python
with open("sore", "rb") as f:
    binary = f.read()

f.close()

binary = binary.replace(b"\xff\x15\x58\xd3\x27\x00", b'\x90'*6)

with open("patched", "wb") as f:
    f.write(binary)
```

Running that it should patch the binary and now we can easily run it

To confirm if the program would do what it says I tried this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/95b6d519-d5a7-4f02-8c0c-12055927db06)

Luckily it wasn't a bluff and now we can brute force

Here's the [script](https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/cyberfest24/scripts/sore/solve.py) I wrote to achieve that

```python
import string
import subprocess

flag = ""
charset = string.ascii_letters + '_{}'

while True:
    for char in charset:
        command = f"echo {flag+char} | ./patched"
        execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, err = execute.communicate()
        print(f"Trying {flag+char}")

        if 'Wrong' not in output:
            flag += char
            break
    
    if flag[-1] == "}":
        break

print(f"FLAG: {flag}")
```

Running it works and I got the flag
[![asciicast](https://asciinema.org/a/MaYoHe5yASPW95v3Nm4DDvFiu.svg)](https://asciinema.org/a/MaYoHe5yASPW95v3Nm4DDvFiu)

```
Flag: ACTF{xor_xor_diff}
```

### Whispers in the Wires

We are given a pcap file and when I opened it in Wireshark I got this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/1ce96d0c-72aa-44c4-b930-07949287b83f)
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/3d576ea6-5f72-484a-9f8f-9e08c2e101fd)

First thing I tried was to get an idea of the protocol hierarchy
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/11d73676-ecc5-41b7-8a67-821fef935c72)

There's HTTP protocol but after checking it I didn't see anything of relevance there

I actually spent lot of time working on this but it was an easy challenge once you just figure it out

I saw that there were various DNS protocol and it looked weird
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/61c95759-a425-4a64-b128-1433608dd230)

The domain queried first was `89504e470d0a1a0a0000000d49484452000002c10000019008060000004f.shadowheadquarters.com`

At this point I knew it was using DNS exfiltration because that's the header of a png file

Incase you don't know what DNS exfiltration is, it's basically a means by which attackers/red-teamers exfiltrates data using the dns protocol

So what we need to do now is to extract all the values from the dns queried then convert it from hex

Actually during the ctf I extracted it manually by using `strings` and some `match & replace magic` but my teammate used a one linear which made life easier
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/c141be71-916c-41ed-bd85-f46eb7b4d70d)

```
tshark -r ctf.pcapng | grep shadowheadquarters.com | grep -v response | cut -d "A" -f 2 | cut -d "." -f 1 | xxd -r -p > lol.png
```

Running that command would decode the image file
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/89ad53b9-0c6a-4c39-9f3a-6fe8ae56b87b)

When we open it we get this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/002326da-07fa-4991-a95a-36f5ec1d1c19)

Just a blue pane image

I went over to [aperisolve](https://www.aperisolve.com/) and got the flag in the `view->superimposed` pane
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/46c02db4-e826-41b4-b40f-efd205c004be)

```
Flag: ACTF{our_secrets_are_in_plain_sight!!}
```

### Hip Hip HIp!
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/0e5c10bb-5696-4341-85f8-c2ff7aff617c)

Just submit that :)

```
Flag: ACTF{Happy_Birthday!_Lytes}
```

Well that's all xD

At the end of the ctf prequalification my team placed 1st while during the final we placed 2nd
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/d27fbef6-1018-4298-a4b0-9a8fd5da877a)

The writeups are mostly the prequalification, since I couldn't attend the final due to exam :(

Byeee!




















