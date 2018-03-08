Call InitCrypto

hProv = 0
if CryptAcquireContext(hProv, "", MS.ENH.RSA.AES.PROV$, PROV.RSA.AES, CRYPT.VERIFYCONTEXT) = 0 then
    print "CryptAcquireContext() failed."
    goto [end]
end if

open "testkey.txt" for binary as #testkey
blob$ = input$(#testkey, lof(#testkey))
close #testkey

print blob$

lenBlob = len(blob$)
hKey = 0
if ( CryptImportKey(hProv, blob$, lenBlob, _NULL, 0, hKey) = 0 ) then
    Print "CryptImportKey() failed."
    goto [RCend]
end if


toHash$ = "askldfjaklsjufioasdfjlkj"
toHashLen = len(toHash$)

hHash = 0
if ( CryptCreateHash(hProv, CALG.SHA.256, 0, 0, hHash) = 0 ) then
    Print "CryptCreateHash() failed - ";GetLastError()
    goto [DKend]
end if


if ( CryptHashData(hHash, toHash$, toHashLen, 0) = 0) then
    Print "CryptHashData() failed - ";GetLastError()
    goto [DHend]
end if


Print "Getting sig length..."

sigLen = 0
if ( CryptSignHash(hHash, AT.KEYEXCHANGE, 0, "", sigLen) = 0) then
    Print "Unable to get signature length - ";GetLastError()
    goto [DHend]
end if


sigBuf$ = space$(sigLen)
if ( CryptSignHash(hHash, AT.KEYEXCHANGE, 0, sigBuf$, sigLen) = 0) then
    Print "Unable to sign hash - ";GetLastError()
    goto [DHend]
end if

print "Signed successfully.  Attempting to verify signature."

a = CryptDestroyHash(hHash)


toHash$ = "askldfjaklsjufioasdfjlkj"
toHashLen = len(toHash$)

hHash = 0
if ( CryptCreateHash(hProv, CALG.SHA.256, 0, 0, hHash) = 0 ) then
    Print "CryptCreateHash() failed - ";GetLastError()
    goto [DKend]
end if


if ( CryptHashData(hHash, toHash$, toHashLen, 0) = 0) then
    Print "CryptHashData() failed - ";GetLastError()
    goto [DHend]
end if

if ( CryptVerifySignature(hHash, sigBuf$, sigLen, hKey, 0) ) then
    Print "Verified signature!"
else
    Print "Unable to verify signature - ";GetLastError()
end if


[DHend]
a = CryptDestroyHash(hHash)

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

