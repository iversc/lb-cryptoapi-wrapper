Call InitCrypto

str$ = "testing"
lenStr = len(str$)

buf$ = ""
bufLen = 0
if CryptBinaryToString(str$, lenStr, CRYPT.STRING.BASE64, buf$, bufLen) = 0 then
    Print "CryptBinaryToString() failed."
    goto [end]
end if

buf$ = space$(bufLen)

if CryptBinaryToString(str$, lenStr, CRYPT.STRING.BASE64, buf$, bufLen) = 0 then
    Print "CryptBinaryToString() failed."
    goto [end]
end if

Print buf$


decBuf$ = ""
decBufLen = 0

if CryptStringToBinary(buf$, bufLen, CRYPT.STRING.BASE64, decBuf$, decBufLen, 0, 0) = 0 then
    Print "CryptStringToBinary() failed."
    goto [end]
end if

Print "Required return buffer - ";decBufLen

decBuf$ = space$(decBufLen)

if CryptStringToBinary(buf$, bufLen, CRYPT.STRING.BASE64, decBuf$, decBufLen, 0, 0) = 0 then
    Print "CryptStringToBinary() failed."
    goto [end]
end if

print decBuf$


hProv = 0
if CryptAcquireContext(hProv, "", MS.ENH.RSA.AES.PROV$, PROV.RSA.AES, 0) = 0 then
    print "CryptAcquireContext() failed."
    goto [end]
end if

hHash = 0
if ( CryptCreateHash(hProv, CALG.SHA.256, 0, 0, hHash) = 0 ) then
    print "CryptCreateHash() failed."
    goto [RCend]
end if


data$ = "testing"
dataLen = len(data$)
if ( CryptHashData(hHash, data$, dataLen, 0) = 0 ) then
    print "CryptHashData() failed."
    goto [DHend]
end if

buf$ = ""
sLen = 0

if ( CryptGetHashSize(hHash, sLen) = 0 ) then
    print "CryptGetHashParam() size failed."
    goto [DHend]
end if

buf$ = space$(sLen)

if ( CryptGetHashValue(hHash, buf$, sLen) = 0 ) then
    print "CryptGetHashParam() failed."
    goto [DHend]
end if

for x = 1 to len(buf$)
    'print asc(mid$(buf$, x, 1))
    a$ = dechex$(asc(mid$(buf$, x, 1)))
    hex$ = hex$ + right$("00" + a$, 2)
next x

Print hex$


[DHend]
a = CryptDestroyHash(hHash)


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
End Sub

Sub EndCrypto
    Close #crypt32
    close #cryptadvapi32
End Sub

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

    CallDLL #cryptadvapi32, "CryptGetHashParam",_
    hHash as ulong,_
    dwParam as long,_
    pData$ as ptr,_
    a as struct,_
    dwFlags as long,_
    CryptGetHashParam as long

    pDataLen = a.pDataLen.struct
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

