'Must begin with InitCrypto, and end with EndCrypto.
Call InitCrypto

'Set up a cryptographic context to use for this session.
'Only context I've included is the MS RSA and AES provider, so I wrote a function to use that as the default.
hProv = GetRSAAESContext()
if hProv = 0 then
    print "CryptAcquireContext() failed - ";GetLastError()
    goto [end]
end if

'Derive an AES-256 encryption key from a password.
Input "Enter encryption password. >";password$


'The derivation is done by hashing the input, as generating a key based on the hash.
'The following helper function takes care of both.
'
'All keys derived are marked as exportable, so the raw key can be saved later with
'CryptExportKey() if wished.
hKey = DeriveAES256Key(hProv, password$)

if hKey = 0 then
    print "Key derivation failed. - ";GetLastError()
    goto [RCend]
end if

print

someData$ = "shortdata"
Print "Encrypting short message - ";someData$
encSomeData$ = AES256Encrypt$(hKey, someData$)
Print "Encrypted message - ";encSomeData$

if encSomeData$ = "" then
    Print "Short encryption failed."
    goto [DKend]
end if


Print
longData$ = "The quick brown fox jumps over the lazy dog."
Print "Encrypting long message - ";longData$
encLongData$ = AES256Encrypt$(hKey, longData$)
print "Encrypted message - ";encLongData$

if encLongData$ = "" then
    Print "Long encryption failed."
    goto [DKend]
end if

'Destroy key, and re-derive, to prove separate keygen and decryption
a = CryptDestroyKey(hKey)


Print

Input "Enter decryption password. >";password$

hKey = DeriveAES256Key(hProv, password$)

if hKey = 0 then
    print "Key derivation failed. - ";GetLastError()
    goto [RCend]
end if

Print "Decrypting short message..."
decSomeData$ = AES256Decrypt$(hKey, encSomeData$)
Print "Decrypted message - ";decSomeData$

if decSomeData$ = "" then
    Print "Short decryption failed."
    goto [DKend]
end if

Print

Print "Decrypting long message..."
decLongData$ = AES256Decrypt$(hKey, encLongData$)
Print "Decrypted message - ";decLongData$

if decLongData$ = "" then
    Print "Long decryption failed."
    goto [DKend]
end if


[DKend]
a = CryptDestroyKey(hKey)

[RCend]
a = CryptReleaseContext(hProv)

[end]
Call EndCrypto


Sub InitCrypto
    Open "crypt32.dll" for DLL as #crypt32
    open "advapi32.dll" for DLL as #cryptadvapi32

    Global CRYPT.STRING.BASE64HEADER
    CRYPT.STRING.BASE64HEADER = 0

    Global CRYPT.STRING.BASE64
    CRYPT.STRING.BASE64 = 1

    Global CRYPT.STRING.BASE64REQUESTHEADER
    CRYPT.STRING.BASE64REQUESTHEADER = 3

    Global CRYPT.STRING.HEX
    CRYPT.STRING.HEX = 4

    Global CRYPT.STRING.HEXASCII
    CRYPT.STRING.HEXASCII = 5

    Global MS.ENH.RSA.AES.PROV$
    MS.ENH.RSA.AES.PROV$ = "Microsoft Enhanced RSA and AES Cryptographic Provider"

    Global CALG.AES.256
    CALG.AES.256 = hexdec("6610")

    Global CALG.RSA.SIGN
    CALG.RSA.SIGN = hexdec("2400")

    Global CALG.RSA.KEYX
    CALG.RSA.KEYX = hexdec("a400")

    Global CALG.SHA.256
    CALG.SHA.256 = hexdec("800c")

    Global PROV.RSA.AES
    PROV.RSA.AES = 24

    Global HP.HASHSIZE
    HP.HASHSIZE = 4

    Global HP.HASHVAL
    HP.HASHVAL = 2

    Global ERROR.MORE.DATA
    ERROR.MORE.DATA = 234

    Global CRYPT.EXPORTABLE
    CRYPT.EXPORTABLE = 1

    Global SIMPLEBLOB
    SIMPLEBLOB = 1

    Global PUBLICKEYBLOB
    PUBLICKEYBLOB = 6

    Global PRIVATEKEYBLOB
    PRIVATEKEYBLOB = 7

    Global PLAINTEXTKEYBLOB
    PLAINTEXTKEYBLOB = 8

    Global AES.BLOCK.SIZE
    AES.BLOCK.SIZE = 16

    Global AT.KEYEXCHANGE
    AT.KEYEXCHANGE = 1

    Global AT.SIGNATURE
    AT.SIGNATURE = 2

    Global RSA2048BIT.KEY
    RSA2048BIT.KEY = hexdec("08000000")

    Global CRYPT.VERIFYCONTEXT
    CRYPT.VERIFYCONTEXT = hexdec("F0000000")
End Sub

Sub EndCrypto
    Close #crypt32
    close #cryptadvapi32
End Sub

Function GetLastError()
    CallDLL #kernel32, "GetLastError",_
    GetLastError as long
End Function

Function GetRSAAESContext()
    hProv = 0
    a = CryptAcquireContext(hProv, "", MS.ENH.RSA.AES.PROV$, PROV.RSA.AES, CRYPT.VERIFYCONTEXT)
    If a = 0 then
        GetRSAAESContext = 0
    Else
        GetRSAAESContext = hProv
    End If
End Function

Function DeriveAES256Key(hProv, pData$)
    DeriveAES256Key = 0
    hHash = 0

    noKey = 0    'SHA256 is not a keyed algorithm, so we pass 0
    noFlags = 0  'We are not using any flags for this hash
    if ( CryptCreateHash(hProv, CALG.SHA.256, noKey, noFlags, hHash) = 0) then
        'Hash creation failed.
        goto [exit]
    end if

    lenData = len(pData$)

    if ( CryptHashData(hHash, pData$, lenData, noFlags) = 0 ) then
        'Hash data failed.
        goto [DHexit]
    end if

    'Now that we have the hash, we can derive the key from it.
    'We do not actually need to obtain the hash ourselves, just
    'pass the handle(hHash) to the Derive function.
    hKey = 0
    if ( CryptDeriveKey(hProv, CALG.AES.256, hHash, CRYPT.EXPORTABLE, hKey) = 0 ) then
        'CryptDeriveKey() failed.
        goto [DHexit]
    end if

    DeriveAES256Key = hKey

    [DHexit]
    'Clear memory for hash when we're done with it
    a = CryptDestroyHash(hHash)

    [exit]
End Function

Function AES256Encrypt$(hKey, data$)
    AES256Encrypt$ = ""
    encBuf$ = ""

    For x = 1 to len(data$) step AES.BLOCK.SIZE
        chunk$ = mid$(data$, x, AES.BLOCK.SIZE)
        cLen = len(chunk$)  'Amount of data in bytes being encrypted in this chunk
        bufLen = int(len(chunk$) / AES.BLOCK.SIZE + 1) * AES.BLOCK.SIZE
        plainBuf$ = chunk$ + space$(bufLen - cLen)  'Size of the whole buffer we're passing in

        noHash = 0  'We are not using the hashing feature of CryptEncrypt for this

        'Is this the final block we're encrypting?
        if x + AES.BLOCK.SIZE > len(data$) then
            Final = 1
        else
            Final = 0
        end if

        noFlags = 0
        if ( CryptEncrypt(hKey, noHash, Final, noFlags, plainBuf$, cLen, bufLen) = 0 ) then
            'CryptEncrypt failed
            goto [exit]
        end if

        'cLen gets updated by CryptEncrypt() to now hold the number of bytes in the encrypted buffer.
        'Add that to our running total of encrypted data.
        encBuf$ = encBuf$ + left$(plainBuf$, cLen)
    Next x

    AES256Encrypt$ = encBuf$
    [exit]
End Function

Function AES256Decrypt$(hKey, encData$)
    AES256Decrypt$ = ""
    decBuf$ = ""

    For x = 1 to len(encData$) step AES.BLOCK.SIZE
        chunk$ = mid$(encData$, x, AES.BLOCK.SIZE)
        cLen = len(chunk$) 'Amount of bytes being decrypted

        noHash = 0  'Not using hash abilty of CryptDecrypt

        'Final chunk?
        if x + AES.BLOCK.SIZE > len(encData$) then
            Final = 1
        else
            Final = 0
        end if

        noFlags = 0
        if ( CryptDecrypt(hKey, noHash, Final, noFlags, chunk$, cLen) = 0) then
            'Decryption failed
            goto [exit]
        end if

        decBuf$ = decBuf$ + left$(chunk$, cLen)
    Next x

    AES256Decrypt$ = decBuf$
    [exit]
End Function

Function CryptAcquireContext(byref hProv, pContainer$, pProvider$, dwProvType, dwFlags)
    struct a, hProv as ulong

    a.hProv.struct = hProv

    if pContainer$ = "" then
        CallDLL #cryptadvapi32, "CryptAcquireContextA",_
        a as struct,_
        _NULL as ulong,_
        pProvider$ as ptr,_
        dwProvType as long,_
        dwFlags as long,_
        CryptAcquireContext as long
    else
        CallDLL #cryptadvapi32, "CryptAcquireContextA",_
        a as struct,_
        pContainer$ as ptr,_
        pProvider$ as ptr,_
        dwProvType as long,_
        dwFlags as long,_
        CryptAcquireContext as long
    end if

    hProv = a.hProv.struct
End Function

Function CryptEncrypt(hKey, hHash, Final, dwFlags, byref pData$, byref pDataLen, dwBufLen)
    struct a, pDataLen as ulong
    a.pDataLen.struct = pDataLen

    if pData$ = "" then
        CallDLL #cryptadvapi32, "CryptEncrypt",_
        hKey as ulong,_
        hHash as ulong,_
        Final as long,_
        dwFlags as long,_
        _NULL as long,_
        a as struct,_
        dwBufLen as long,_
        CryptEncrypt as long
    else
        CallDLL #cryptadvapi32, "CryptEncrypt",_
        hKey as ulong,_
        hHash as ulong,_
        Final as long,_
        dwFlags as long,_
        pData$ as ptr,_
        a as struct,_
        dwBufLen as long,_
        CryptEncrypt as long
    end if

    pDataLen = a.pDataLen.struct
End Function

Function CryptSignHash(hHash, dwKeySpec, dwFlags, byref pbSignature$, byref pdwSigLen)
    struct a, pdwSigLen as long
    a.pdwSigLen.struct = pdwSigLen

    if pbSignature$ = "" then
        CallDLL #cryptadvapi32, "CryptSignHashA",_
        hHash as ulong,_
        dwKeySpec as long,_
        _NULL as long,_
        dwFlags as long,_
        _NULL as long,_
        a as struct,_
        CryptSignHash as long
    else
        CallDLL #cryptadvapi32, "CryptSignHashA",_
        hHash as ulong,_
        dwKeySpec as long,_
        _NULL as long,_
        dwFlags as long,_
        pbSignature$ as ptr,_
        a as struct,_
        CryptSignHash as long
    end if

    pdwSigLen = a.pdwSigLen.struct
End Function

Function CryptVerifySignature(hHash, pbSignature$, dwSigLen, hPubKey, dwFlags)
    CallDLL #cryptadvapi32, "CryptVerifySignatureA",_
    hHash as ulong,_
    pbSignature$ as ptr,_
    dwSigLen as long,_
    hPubKey as ulong,_
    _NULL as long,_
    dwFlags as long,_
    CryptVerifySignature as long
End Function

Function CryptDecrypt(hKey, hHash, Final, dwFlags, byref pData$, byref pDataLen)
    struct a, pDataLen as ulong
    a.pDataLen.struct = pDataLen

    if pData$ = "" then
        CallDLL #cryptadvapi32, "CryptDecrypt",_
        hKey as ulong,_
        hHash as ulong,_
        Final as long,_
        dwFlags as long,_
        _NULL as long,_
        a as struct,_
        CryptDecrypt as long
    else
        CallDLL #cryptadvapi32, "CryptDecrypt",_
        hKey as ulong,_
        hHash as ulong,_
        Final as long,_
        dwFlags as long,_
        pData$ as ptr,_
        a as struct,_
        CryptDecrypt as long
    end if

    pDataLen = a.pDataLen.struct
End Function

Function CryptGenKey(hProv, algId, dwFlags, byref hKey)
    struct a, hKey as ulong

    CallDLL #cryptadvapi32, "CryptGenKey",_
    hProv as ulong,_
    algId as long,_
    dwFlags as long,_
    a as struct,_
    CryptGenKey as long

    hKey = a.hKey.struct
End Function

Function CryptDeriveKey(hProv, algId, hBaseData, dwFlags, byref pKey)
    struct a, pKey as ulong

    CallDLL #cryptadvapi32, "CryptDeriveKey",_
    hProv as ulong,_
    algId as long,_
    hBaseData as ulong,_
    dwFlags as long,_
    a as struct,_
    CryptDeriveKey as long

    pKey = a.pKey.struct
End Function

Function CryptDestroyKey(hKey)
    CallDLL #cryptadvapi32, "CryptDestroyKey",_
    hKey as ulong,_
    CryptDestroyKey as long
End Function

Function CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, byref pbData$, byref pdwDataLen)
    struct a, pdwDataLen as long
    a.pdwDataLen.struct = pdwDataLen

    if pbData$ = "" then
        CallDLL #cryptadvapi32, "CryptExportKey",_
        hKey as ulong,_
        hExpKey as ulong,_
        dwBlobType as long,_
        dwFlags as long,_
        _NULL as ulong,_
        a as struct,_
        CryptExportKey as long
    else
        CallDLL #cryptadvapi32, "CryptExportKey",_
        hKey as ulong,_
        hExpKey as ulong,_
        dwBlobType as long,_
        dwFlags as long,_
        pbData$ as ptr,_
        a as struct,_
        CryptExportKey as long
    end if

    pdwDataLen = a.pdwDataLen.struct
End Function

Function CryptImportKey(hProv, pData$, dwDataLen, hPubKey, dwFlags, byref hKey)
    struct a, hKey as ulong

    CallDLL #cryptadvapi32, "CryptImportKey",_
    hProv as ulong,_
    pData$ as ptr,_
    dwDataLen as long,_
    hPubKey as ulong,_
    dwFlags as long,_
    a as struct,_
    CryptImportKey as long

    hKey = a.hKey.struct
End Function

Function CryptCreateHash(hProv, algId, hKey, dwFlags, byref pHash)
    struct a, pHash as ulong

    CallDLL #cryptadvapi32, "CryptCreateHash",_
    hProv as ulong,_
    algId as long,_
    hKey as ulong,_
    dwFlags as long,_
    a as struct,_
    CryptCreateHash as long

    pHash = a.pHash.struct
End Function

Function CryptDestroyHash(hHash)
    CallDLL #cryptadvapi32, "CryptDestroyHash",_
    hHash as ulong,_
    CryptDestroyHash as long
End Function

Function CryptHashData(hHash, pData$, dataLen, dwFlags)
    CallDLL #cryptadvapi32, "CryptHashData",_
    hHash as ulong,_
    pData$ as ptr,_
    dataLen as long,_
    dwFlags as long,_
    CryptHashData as long
End Function

Function CryptGetHashSize(hHash, byref bSize)
    struct a, bSize as long

    struct b, size as long

    b.size.struct = len(a.struct)

    CallDLL #cryptadvapi32, "CryptGetHashParam",_
    hHash as ulong,_
    HP.HASHSIZE as long,_
    a as struct,_
    b as struct,_
    0 as long,_
    CryptGetHashSize as long

    bSize = a.bSize.struct
End Function

Function CryptGetHashValue(hHash, byref pData$, byref pDataLen)
    struct a, pDataLen as long
    a.pDataLen.struct = pDataLen

    CallDLL #cryptadvapi32, "CryptGetHashParam",_
    hHash as ulong,_
    HP.HASHVAL as long,_
    pData$ as ptr,_
    a as struct,_
    0 as long,_
    CryptGetHashValue as long

    pDataLen = a.pDataLen.struct
End Function

Function CryptGetHashParam(hHash, dwParam, byref pData$, byref pDataLen, dwFlags)
    struct a, pDataLen as long

    a.pDataLen.struct = pDataLen

    if pData$ = "" then
        CallDLL #cryptadvapi32, "CryptGetHashParam",_
        hHash as ulong,_
        dwParam as long,_
        _NULL as long,_
        a as struct,_
        dwFlags as long,_
        CryptGetHashParam as long
    else
        CallDLL #cryptadvapi32, "CryptGetHashParam",_
        hHash as ulong,_
        dwParam as long,_
        pData$ as ptr,_
        a as struct,_
        dwFlags as long,_
        CryptGetHashParam as long
    end if

    pDataLen = a.pDataLen.struct
End Function

Function CryptSetHashParam(hHash, dwParam, pbData$, dwFlags)
    CallDLL #cryptadvapi32, "CryptSetHashParam",_
    hHash as ulong,_
    dwParam as long,_
    pbData$ as ptr,_
    dwFlags as long,_
    CryptSetHashParam as long
End Function

Function CryptReleaseContext(hProv)
    CallDLL #cryptadvapi32, "CryptReleaseContext",_
    hProv as ulong,_
    0 as long,_
    CryptReleaseContext as long
End Function

Function CryptBinaryToString(pBinary$, cbBinary, dwFlags, byref pszString$, byref strLen)
    struct a, strLen as ulong
    a.strLen.struct = strLen

    if strLen = 0 then
        CallDLL #crypt32, "CryptBinaryToStringA",_
        pBinary$ as ptr,_
        cbBinary as ulong,_
        dwFlags as ulong,_
        0 as ulong,_
        a as struct,_
        CryptBinaryToString as long
    else
        CallDLL #crypt32, "CryptBinaryToStringA",_
        pBinary$ as ptr,_
        cbBinary as ulong,_
        dwFlags as ulong,_
        pszString$ as ptr,_
        a as struct,_
        CryptBinaryToString as long
    end if

    strLen = a.strLen.struct
End Function

Function CryptStringToBinary(pString$, cbString, dwFlags, byref pBinary$, byref cBinary, byref pdwSkip, byref pdwFlags)
    struct a, binLen as ulong
    a.binLen.struct = cBinary

    struct b, pdwSkip as long
    b.pdwSkip.struct = pdwSkip

    struct c, pdwFlags as long
    c.pdwFlags.struct = pdwFlags

    if cBinary = 0 then
        CallDLL #crypt32, "CryptStringToBinaryA",_
        pString$ as ptr,_
        cbString as ulong,_
        dwFlags as ulong,_
        0 as long,_
        a as struct,_
        b as struct,_
        c as struct,_
        CryptStringToBinary as long
    else
        CallDLL #crypt32, "CryptStringToBinaryA",_
        pString$ as ptr,_
        cbString as ulong,_
        dwFlags as ulong,_
        pBinary$ as ptr,_
        a as struct,_
        b as struct,_
        c as struct,_
        CryptStringToBinary as long
    end if

    cBinary = a.binLen.struct
    pdwSkip = b.pdwSkip.struct
    pdwFlags = c.pdwFlags.struct
End Function

