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

a = CryptReleaseContext(hProv)

[end]
Call EndCrypto


Sub InitCrypto
    Open "crypt32.dll" for DLL as #crypt32
    open "advapi32.dll" for DLL as #advapi32

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
End Sub

Sub EndCrypto
    Close #crypt32
    close #advapi32
End Sub

Function CryptAcquireContext(byref hProv, pContainer$, pProvider$, dwProvType, dwFlags)
    struct a, hProv as ulong

    a.hProv.struct = hProv

    if pContainer$ = "" then
        CallDLL #advapi32, "CryptAcquireContextA",_
        a as struct,_
        _NULL as ulong,_
        pProvider$ as ptr,_
        dwProvType as long,_
        dwFlags as long,_
        CryptAcquireContext as long
    else
        CallDLL #advapi32, "CryptAcquireContextA",_
        a as struct,_
        pContainer$ as ptr,_
        pProvider$ as ptr,_
        dwProvType as long,_
        dwFlags as long,_
        CryptAcquireContext as long
    end if

    hProv = a.hProv.struct
End Function

Function CryptReleaseContext(hProv)
    CallDLL #advapi32, "CryptReleaseContext",_
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

