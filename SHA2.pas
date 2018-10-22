{-------------------------------------------------------------------------------

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.

-------------------------------------------------------------------------------}
{===============================================================================

  SHA2 Hash Calculation

  ©František Milt 2018-10-22

  Version 1.0.6

  Following hash sizes are supported in current implementation:
    SHA-224
    SHA-256
    SHA-384
    SHA-512
    SHA-512/224
    SHA-512/256

  Dependencies:
    AuxTypes    - github.com/ncs-sniper/Lib.AuxTypes
    StrRect     - github.com/ncs-sniper/Lib.StrRect
    BitOps      - github.com/ncs-sniper/Lib.BitOps
  * SimpleCPUID - github.com/ncs-sniper/Lib.SimpleCPUID

  SimpleCPUID might not be needed, see BitOps library for details.

===============================================================================}
unit SHA2;

{$DEFINE LargeBuffer}

{$IFDEF ENDIAN_BIG}
  {$MESSAGE FATAL 'Big-endian system not supported'}
{$ENDIF}

{$IFOPT Q+}
  {$DEFINE OverflowCheck}
{$ENDIF}

{$IFDEF FPC}
  {$MODE ObjFPC}{$H+}
  {$INLINE ON}
  {$DEFINE CanInline}
  {$DEFINE FPC_DisableWarns}
  {$MACRO ON}
{$ELSE}
  {$IF CompilerVersion >= 17 then}  // Delphi 2005+
    {$DEFINE CanInline}
  {$ELSE}
    {$UNDEF CanInline}
  {$IFEND}
{$ENDIF}

interface

uses
  Classes, AuxTypes;

type
  TOctaWord = record
    case Integer of
      0:(Lo,Hi:   UInt64);
      1:(Bytes:   array[0..15] of UInt8);
      2:(Words:   array[0..7] of UInt16);
      3:(DWords:  array[0..3] of UInt32);
      4:(QWords:  array[0..1] of UInt64);
  end;
  POctaWord = ^TOctaWord;
  OctaWord = TOctaWord;

const
  ZeroOctaWord: OctaWord = (Lo: 0; Hi: 0);

type
  TSHA2Hash_32 = record
    PartA:  UInt32;
    PartB:  UInt32;
    PartC:  UInt32;
    PartD:  UInt32;
    PartE:  UInt32;
    PartF:  UInt32;
    PartG:  UInt32;
    PartH:  UInt32;
  end;

  TSHA2Hash_224 = type TSHA2Hash_32;
  TSHA2Hash_256 = type TSHA2Hash_32;

  TSHA2Hash_64 = record
    PartA:  UInt64;
    PartB:  UInt64;
    PartC:  UInt64;
    PartD:  UInt64;
    PartE:  UInt64;
    PartF:  UInt64;
    PartG:  UInt64;
    PartH:  UInt64;
  end;

  TSHA2Hash_384 = type TSHA2Hash_64;
  TSHA2Hash_512 = type TSHA2Hash_64;

  TSHA2Hash_512_224 = type TSHA2Hash_512;
  TSHA2Hash_512_256 = type TSHA2Hash_512;

  TSHA2HashSize = (sha224, sha256, sha384, sha512, sha512_224, sha512_256);

  TSHA2Hash = record
    case HashSize: TSHA2HashSize of
      sha224:     (Hash224:     TSHA2Hash_224);
      sha256:     (Hash256:     TSHA2Hash_256);
      sha384:     (Hash384:     TSHA2Hash_384);
      sha512:     (Hash512:     TSHA2Hash_512);
      sha512_224: (Hash512_224: TSHA2Hash_512_224);
      sha512_256: (Hash512_256: TSHA2Hash_512_256);
  end;

const
  InitialSHA2_224: TSHA2Hash_224 =(
    PartA: $C1059ED8;
    PartB: $367CD507;
    PartC: $3070DD17;
    PartD: $F70E5939;
    PartE: $FFC00B31;
    PartF: $68581511;
    PartG: $64F98FA7;
    PartH: $BEFA4FA4);

  InitialSHA2_256: TSHA2Hash_256 =(
    PartA: $6A09E667;
    PartB: $BB67AE85;
    PartC: $3C6Ef372;
    PartD: $A54ff53A;
    PartE: $510E527f;
    PartF: $9B05688C;
    PartG: $1F83d9AB;
    PartH: $5BE0CD19);

  InitialSHA2_384: TSHA2Hash_384 =(
    PartA: UInt64($CBBB9D5DC1059ED8);
    PartB: UInt64($629A292A367CD507);
    PartC: UInt64($9159015A3070DD17);
    PartD: UInt64($152FECD8F70E5939);
    PartE: UInt64($67332667FFC00B31);
    PartF: UInt64($8EB44A8768581511);
    PartG: UInt64($DB0C2E0D64F98FA7);
    PartH: UInt64($47B5481DBEFA4FA4));

  InitialSHA2_512: TSHA2Hash_512 =(
    PartA: UInt64($6A09E667F3BCC908);
    PartB: UInt64($BB67AE8584CAA73B);
    PartC: UInt64($3C6EF372FE94F82B);
    PartD: UInt64($A54FF53A5F1D36F1);
    PartE: UInt64($510E527FADE682D1);
    PartF: UInt64($9B05688C2B3E6C1F);
    PartG: UInt64($1F83D9ABFB41BD6B);
    PartH: UInt64($5BE0CD19137E2179));

  InitialSHA2_512mod: TSHA2Hash_512 =(
    PartA: UInt64($CFAC43C256196CAD);
    PartB: UInt64($1EC20B20216F029E);
    Partc: UInt64($99CB56D75B315D8E);
    PartD: UInt64($00EA509FFAB89354);
    PartE: UInt64($F4ABF7DA08432774);
    PartF: UInt64($3EA0CD298E9BC9BA);
    PartG: UInt64($BA267C0E5EE418CE);
    PartH: UInt64($FE4568BCB6DB84DC));

  ZeroSHA2_224: TSHA2Hash_224 = (PartA: 0; PartB: 0; PartC: 0; PartD: 0;
                                 PartE: 0; PartF: 0; PartG: 0; PartH: 0);    
  ZeroSHA2_256: TSHA2Hash_256 = (PartA: 0; PartB: 0; PartC: 0; PartD: 0;
                                 PartE: 0; PartF: 0; PartG: 0; PartH: 0);
  ZeroSHA2_384: TSHA2Hash_384 = (PartA: 0; PartB: 0; PartC: 0; PartD: 0;
                                 PartE: 0; PartF: 0; PartG: 0; PartH: 0);
  ZeroSHA2_512: TSHA2Hash_512 = (PartA: 0; PartB: 0; PartC: 0; PartD: 0;
                                 PartE: 0; PartF: 0; PartG: 0; PartH: 0);

  ZeroSHA2_512_224: TSHA2Hash_512_224 = (PartA: 0; PartB: 0; PartC: 0; PartD: 0;
                                         PartE: 0; PartF: 0; PartG: 0; PartH: 0);
  ZeroSHA2_512_256: TSHA2Hash_512_256 = (PartA: 0; PartB: 0; PartC: 0; PartD: 0;
                                         PartE: 0; PartF: 0; PartG: 0; PartH: 0);

//------------------------------------------------------------------------------

Function BuildOctaWord(Lo,Hi: UInt64): OctaWord;

Function InitialSHA2_512_224: TSHA2Hash_512_224;
Function InitialSHA2_512_256: TSHA2Hash_512_256;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash_224): String; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function SHA2ToStr(Hash: TSHA2Hash_256): String; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function SHA2ToStr(Hash: TSHA2Hash_384): String; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function SHA2ToStr(Hash: TSHA2Hash_512): String; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function SHA2ToStr(Hash: TSHA2Hash_512_224): String; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function SHA2ToStr(Hash: TSHA2Hash_512_256): String; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function SHA2ToStr(Hash: TSHA2Hash): String; overload;

Function StrToSHA2_224(Str: String): TSHA2Hash_224;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function StrToSHA2_256(Str: String): TSHA2Hash_256;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function StrToSHA2_384(Str: String): TSHA2Hash_384;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function StrToSHA2_512(Str: String): TSHA2Hash_512;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function StrToSHA2_512_224(Str: String): TSHA2Hash_512_224;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function StrToSHA2_512_256(Str: String): TSHA2Hash_512_256;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function StrToSHA2(HashSize: TSHA2HashSize; Str: String): TSHA2Hash;

Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_224): Boolean; overload;
Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_256): Boolean; overload;
Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_384): Boolean; overload;
Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_512): Boolean; overload;
Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_512_224): Boolean; overload;
Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_512_256): Boolean; overload;
Function TryStrToSHA2(HashSize: TSHA2HashSize; const Str: String; out Hash: TSHA2Hash): Boolean; overload;

Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_224): TSHA2Hash_224; overload;
Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_256): TSHA2Hash_256; overload;
Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_384): TSHA2Hash_384; overload;
Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_512): TSHA2Hash_512; overload;
Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_512_224): TSHA2Hash_512_224; overload;
Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_512_256): TSHA2Hash_512_256; overload;
Function StrToSHA2Def(HashSize: TSHA2HashSize; const Str: String; Default: TSHA2Hash): TSHA2Hash; overload;

Function CompareSHA2(A,B: TSHA2Hash_224): Integer; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function CompareSHA2(A,B: TSHA2Hash_256): Integer; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function CompareSHA2(A,B: TSHA2Hash_384): Integer; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function CompareSHA2(A,B: TSHA2Hash_512): Integer; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function CompareSHA2(A,B: TSHA2Hash_512_224): Integer; overload;
Function CompareSHA2(A,B: TSHA2Hash_512_256): Integer; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function CompareSHA2(A,B: TSHA2Hash): Integer; overload;

Function SameSHA2(A,B: TSHA2Hash_224): Boolean; overload;
Function SameSHA2(A,B: TSHA2Hash_256): Boolean; overload;
Function SameSHA2(A,B: TSHA2Hash_384): Boolean; overload;
Function SameSHA2(A,B: TSHA2Hash_512): Boolean; overload;
Function SameSHA2(A,B: TSHA2Hash_512_224): Boolean; overload;
Function SameSHA2(A,B: TSHA2Hash_512_256): Boolean; overload;
Function SameSHA2(A,B: TSHA2Hash): Boolean; overload;

Function BinaryCorrectSHA2(Hash: TSHA2Hash_224): TSHA2Hash_224; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function BinaryCorrectSHA2(Hash: TSHA2Hash_256): TSHA2Hash_256; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function BinaryCorrectSHA2(Hash: TSHA2Hash_384): TSHA2Hash_384; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function BinaryCorrectSHA2(Hash: TSHA2Hash_512): TSHA2Hash_512; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function BinaryCorrectSHA2(Hash: TSHA2Hash_512_224): TSHA2Hash_512_224; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function BinaryCorrectSHA2(Hash: TSHA2Hash_512_256): TSHA2Hash_512_256; overload;{$IF Defined(CanInline) and Defined(FPC)} inline; {$IFEND}
Function BinaryCorrectSHA2(Hash: TSHA2Hash): TSHA2Hash; overload;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash_224; const Buffer; Size: TMemSize); overload;
procedure BufferSHA2(var Hash: TSHA2Hash_256; const Buffer; Size: TMemSize); overload;
procedure BufferSHA2(var Hash: TSHA2Hash_384; const Buffer; Size: TMemSize); overload;
procedure BufferSHA2(var Hash: TSHA2Hash_512; const Buffer; Size: TMemSize); overload;
procedure BufferSHA2(var Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize); overload;
procedure BufferSHA2(var Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize); overload;
procedure BufferSHA2(var Hash: TSHA2Hash; const Buffer; Size: TMemSize); overload;

Function LastBufferSHA2(Hash: TSHA2Hash_224; const Buffer; Size: TMemSize; MessageLength: UInt64): TSHA2Hash_224; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_256; const Buffer; Size: TMemSize; MessageLength: UInt64): TSHA2Hash_256; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_384; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_512; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_512_224; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_512_256; overload;

Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_384; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_512; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_512_224; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_512_256; overload;

Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_384; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_512; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_512_224; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_512_256; overload;

Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize; MessageLength: UInt64): TSHA2Hash; overload;
Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash; overload;
Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash; overload;

Function LastBufferSHA2(Hash: TSHA2Hash_224; const Buffer; Size: TMemSize): TSHA2Hash_224; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_256; const Buffer; Size: TMemSize): TSHA2Hash_256; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize): TSHA2Hash_384; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize): TSHA2Hash_512; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize): TSHA2Hash_512_224; overload;
Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize): TSHA2Hash_512_256; overload;
Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize): TSHA2Hash; overload;

//------------------------------------------------------------------------------

Function BufferSHA2(HashSize: TSHA2HashSize; const Buffer; Size: TMemSize): TSHA2Hash; overload;

Function AnsiStringSHA2(HashSize: TSHA2HashSize; const Str: AnsiString): TSHA2Hash;{$IFDEF CanInline} inline; {$ENDIF}
Function WideStringSHA2(HashSize: TSHA2HashSize; const Str: WideString): TSHA2Hash;{$IFDEF CanInline} inline; {$ENDIF}
Function StringSHA2(HashSize: TSHA2HashSize; const Str: String): TSHA2Hash;{$IFDEF CanInline} inline; {$ENDIF}

Function StreamSHA2(HashSize: TSHA2HashSize; Stream: TStream; Count: Int64 = -1): TSHA2Hash;
Function FileSHA2(HashSize: TSHA2HashSize; const FileName: String): TSHA2Hash;

//------------------------------------------------------------------------------

type
  TSHA2Context = type Pointer;

Function SHA2_Init(HashSize: TSHA2HashSize): TSHA2Context;
procedure SHA2_Update(Context: TSHA2Context; const Buffer; Size: TMemSize);
Function SHA2_Final(var Context: TSHA2Context; const Buffer; Size: TMemSize): TSHA2Hash; overload;
Function SHA2_Final(var Context: TSHA2Context): TSHA2Hash; overload;
Function SHA2_Hash(HashSize: TSHA2HashSize; const Buffer; Size: TMemSize): TSHA2Hash;

implementation

uses
  SysUtils, Math, BitOps, StrRect;

{$IFDEF FPC_DisableWarns}
  {$DEFINE FPCDWM}
  {$DEFINE W4055:={$WARN 4055 OFF}} // Conversion between ordinals and pointers is not portable
  {$DEFINE W4056:={$WARN 4056 OFF}} // Conversion between ordinals and pointers is not portable
  {$PUSH}{$WARN 2005 OFF} // Comment level $1 found
  {$IF Defined(FPC) and (FPC_FULLVERSION >= 30000)}
    {$DEFINE W5092:={$WARN 5092 OFF}} // Variable "$1" of a managed type does not seem to be initialized
  {$ELSE}
    {$DEFINE W5092:=}
  {$IFEND}
  {$POP}
{$ENDIF}

const
  BlockSize_32    = 64;                             // 512 bits
  BlockSize_64    = 128;                            // 1024 bits
{$IFDEF LargeBuffers}
  BlocksPerBuffer = 16384;                          // 1MiB BufferSize (32b block)
{$ELSE}
  BlocksPerBuffer = 64;                             // 4KiB BufferSize (32b block)
{$ENDIF}
  BufferSize      = BlocksPerBuffer * BlockSize_32; // Size of read buffer

  RoundConsts_32: array[0..63] of UInt32 = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5, $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC, $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7, $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13, $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3, $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5, $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208, $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2);

  RoundConsts_64: array[0..79] of UInt64 = (
    UInt64($428A2F98D728AE22), UInt64($7137449123EF65CD), UInt64($B5C0FBCFEC4D3B2F), UInt64($E9B5DBA58189DBBC),
    UInt64($3956C25BF348B538), UInt64($59F111F1B605D019), UInt64($923F82A4AF194F9B), UInt64($AB1C5ED5DA6D8118),
    UInt64($D807AA98A3030242), UInt64($12835B0145706FBE), UInt64($243185BE4EE4B28C), UInt64($550C7DC3D5FFB4E2),
    UInt64($72BE5D74F27B896F), UInt64($80DEB1FE3B1696B1), UInt64($9BDC06A725C71235), UInt64($C19BF174CF692694),
    UInt64($E49B69C19EF14AD2), UInt64($EFBE4786384F25E3), UInt64($0FC19DC68B8CD5B5), UInt64($240CA1CC77AC9C65),
    UInt64($2DE92C6F592B0275), UInt64($4A7484AA6EA6E483), UInt64($5CB0A9DCBD41FBD4), UInt64($76F988DA831153B5),
    UInt64($983E5152EE66DFAB), UInt64($A831C66D2DB43210), UInt64($B00327C898FB213F), UInt64($BF597FC7BEEF0EE4),
    UInt64($C6E00BF33DA88FC2), UInt64($D5A79147930AA725), UInt64($06CA6351E003826F), UInt64($142929670A0E6E70),
    UInt64($27B70A8546D22FFC), UInt64($2E1B21385C26C926), UInt64($4D2C6DFC5AC42AED), UInt64($53380D139D95B3DF),
    UInt64($650A73548BAF63DE), UInt64($766A0ABB3C77B2A8), UInt64($81C2C92E47EDAEE6), UInt64($92722C851482353B),
    UInt64($A2BFE8A14CF10364), UInt64($A81A664BBC423001), UInt64($C24B8B70D0F89791), UInt64($C76C51A30654BE30),
    UInt64($D192E819D6EF5218), UInt64($D69906245565A910), UInt64($F40E35855771202A), UInt64($106AA07032BBD1B8),
    UInt64($19A4C116B8D2D0C8), UInt64($1E376C085141AB53), UInt64($2748774CDF8EEB99), UInt64($34B0BCB5E19B48A8),
    UInt64($391C0CB3C5C95A63), UInt64($4ED8AA4AE3418ACB), UInt64($5B9CCA4F7763E373), UInt64($682E6FF3D6B2B8A3),
    UInt64($748F82EE5DEFB2FC), UInt64($78A5636F43172F60), UInt64($84C87814A1F0AB72), UInt64($8CC702081A6439EC),
    UInt64($90BEFFFA23631E28), UInt64($A4506CEBDE82BDE9), UInt64($BEF9A3F7B2C67915), UInt64($C67178F2E372532B),
    UInt64($CA273ECEEA26619C), UInt64($D186B8C721C0C207), UInt64($EADA7DD6CDE0EB1E), UInt64($F57D4F7FEE6ED178),
    UInt64($06F067AA72176FBA), UInt64($0A637DC5A2C898A6), UInt64($113F9804BEF90DAE), UInt64($1B710B35131C471B),
    UInt64($28DB77F523047D84), UInt64($32CAAB7B40C72493), UInt64($3C9EBE0A15C9BEBC), UInt64($431D67C49C100D4C),
    UInt64($4CC5D4BECB3E42B6), UInt64($597F299CFC657E2A), UInt64($5FCB6FAB3AD6FAEC), UInt64($6C44198C4A475817));

type
  TBlockBuffer_32 = array[0..BlockSize_32 - 1] of UInt8;
  PBlockBuffer_32 = ^TBlockBuffer_32;
  TBlockBuffer_64 = array[0..BlockSize_64 - 1] of UInt8;
  PBlockBuffer_64 = ^TBlockBuffer_64;

  TSHA2Context_Internal = record
    MessageHash:      TSHA2Hash;
    MessageLength:    OctaWord;
    TransferSize:     UInt32;
    TransferBuffer:   TBlockBuffer_64;
    ActiveBlockSize:  UInt32;
  end;
  PSHA2Context_Internal = ^TSHA2Context_Internal;

//==============================================================================

Function EndianSwap(Value: OctaWord): OctaWord; overload;
begin
Result.Hi := EndianSwap(Value.Lo);
Result.Lo := EndianSwap(Value.Hi);
end;

//------------------------------------------------------------------------------

Function SizeToMessageLength(Size: UInt64): OctaWord;
begin
Result.Hi := UInt64(Size shr 61);
Result.Lo := UInt64(Size shl 3);
end;

//------------------------------------------------------------------------------

procedure IncOctaWord(var Value: OctaWord; Increment: OctaWord);
var
  Result: UInt64;
  Carry:  UInt32;
  i:      Integer;
begin
Carry := 0;
For i := Low(Value.DWords) to High(Value.DWords) do
  begin
    Result := UInt64(Carry) + Value.DWords[i] + Increment.DWords[i];
    Value.DWords[i] := Int64Rec(Result).Lo;
    Carry := Int64Rec(Result).Hi;
  end;
end;

//==============================================================================

Function BlockHash_32(Hash: TSHA2Hash_32; const Block): TSHA2Hash_32;
var
  i:            Integer;
  Temp1,Temp2:  UInt32;
  Schedule:     array[0..63] of UInt32;
  BlockWords:   array[0..15] of UInt32 absolute Block;
begin
Result := Hash;
For i := 0 to 15 do Schedule[i] := EndianSwap(BlockWords[i]);
{$IFDEF OverflowCheck}{$Q-}{$ENDIF}
For i := 16 to 63 do
  Schedule[i] := UInt32(Schedule[i - 16] + (ROR(Schedule[i - 15],7) xor ROR(Schedule[i - 15],18) xor (Schedule[i - 15] shr 3)) +
                        Schedule[i - 7] + (ROR(Schedule[i - 2],17) xor ROR(Schedule[i - 2],19) xor (Schedule[i - 2] shr 10)));
For i := 0 to 63 do
  begin
    Temp1 := UInt32(Hash.PartH + (ROR(Hash.PartE,6) xor ROR(Hash.PartE,11) xor ROR(Hash.PartE,25)) +
                  ((Hash.PartE and Hash.PartF) xor ((not Hash.PartE) and Hash.PartG)) + RoundConsts_32[i] + Schedule[i]);
    Temp2 := UInt32((ROR(Hash.PartA,2) xor ROR(Hash.PartA,13) xor ROR(Hash.PartA,22)) +
                   ((Hash.PartA and Hash.PartB) xor (Hash.PartA and Hash.PartC) xor (Hash.PartB and Hash.PartC)));
    Hash.PartH := Hash.PartG;
    Hash.PartG := Hash.PartF;
    Hash.PartF := Hash.PartE;
    Hash.PartE := UInt32(Hash.PartD + Temp1);
    Hash.PartD := Hash.PartC;
    Hash.PartC := Hash.PartB;
    Hash.PartB := Hash.PartA;
    Hash.PartA := UInt32(Temp1 + Temp2);
  end;
Result.PartA := UInt32(Result.PartA + Hash.PartA);
Result.PartB := UInt32(Result.PartB + Hash.PartB);
Result.PartC := UInt32(Result.PartC + Hash.PartC);
Result.PartD := UInt32(Result.PartD + Hash.PartD);
Result.PartE := UInt32(Result.PartE + Hash.PartE);
Result.PartF := UInt32(Result.PartF + Hash.PartF);
Result.PartG := UInt32(Result.PartG + Hash.PartG);
Result.PartH := UInt32(Result.PartH + Hash.PartH);
{$IFDEF OverflowCheck}{$Q+}{$ENDIF}
end;

//------------------------------------------------------------------------------

Function BlockHash_64(Hash: TSHA2Hash_64; const Block): TSHA2Hash_64;
var
  i:            Integer;
  Temp1,Temp2:  UInt64;
  Schedule:     array[0..79] of UInt64;
  BlockWords:   array[0..15] of UInt64 absolute Block;
begin
Result := Hash;
For i := 0 to 15 do Schedule[i] := EndianSwap(BlockWords[i]);
{$IFDEF OverflowCheck}{$Q-}{$ENDIF}
For i := 16 to 79 do
  Schedule[i] := UInt64(Schedule[i - 16] + (ROR(Schedule[i - 15],1) xor ROR(Schedule[i - 15],8) xor (Schedule[i - 15] shr 7)) +
                        Schedule[i - 7] + (ROR(Schedule[i - 2],19) xor ROR(Schedule[i - 2],61) xor (Schedule[i - 2] shr 6)));
For i := 0 to 79 do
  begin
    Temp1 := UInt64(Hash.PartH + (ROR(Hash.PartE,14) xor ROR(Hash.PartE,18) xor ROR(Hash.PartE,41)) +
                  ((Hash.PartE and Hash.PartF) xor ((not Hash.PartE) and Hash.PartG)) + RoundConsts_64[i] + Schedule[i]);
    Temp2 := UInt64((ROR(Hash.PartA,28) xor ROR(Hash.PartA,34) xor ROR(Hash.PartA,39)) +
                   ((Hash.PartA and Hash.PartB) xor (Hash.PartA and Hash.PartC) xor (Hash.PartB and Hash.PartC)));
    Hash.PartH := Hash.PartG;
    Hash.PartG := Hash.PartF;
    Hash.PartF := Hash.PartE;
    Hash.PartE := UInt64(Hash.PartD + Temp1);
    Hash.PartD := Hash.PartC;
    Hash.PartC := Hash.PartB;
    Hash.PartB := Hash.PartA;
    Hash.PartA := UInt64(Temp1 + Temp2);
  end;
Result.PartA := UInt64(Result.PartA + Hash.PartA);
Result.PartB := UInt64(Result.PartB + Hash.PartB);
Result.PartC := UInt64(Result.PartC + Hash.PartC);
Result.PartD := UInt64(Result.PartD + Hash.PartD);
Result.PartE := UInt64(Result.PartE + Hash.PartE);
Result.PartF := UInt64(Result.PartF + Hash.PartF);
Result.PartG := UInt64(Result.PartG + Hash.PartG);
Result.PartH := UInt64(Result.PartH + Hash.PartH);
{$IFDEF OverflowCheck}{$Q+}{$ENDIF}
end;

//==============================================================================
//------------------------------------------------------------------------------
//==============================================================================

Function BuildOctaWord(Lo,Hi: UInt64): OctaWord;
begin
Result.Lo := Lo;
Result.Hi := Hi;
end;

//==============================================================================

Function InitialSHA2_512_224: TSHA2Hash_512_224;
var
  EvalStr: AnsiString;
begin
EvalStr := StrToAnsi('SHA-512/224');
Result := TSHA2Hash_512_224(LastBufferSHA2(InitialSHA2_512mod,PAnsiChar(EvalStr)^,Length(EvalStr) * SizeOf(AnsiChar)));
end;

//------------------------------------------------------------------------------

Function InitialSHA2_512_256: TSHA2Hash_512_256;
var
  EvalStr: AnsiString;
begin
EvalStr := StrToAnsi('SHA-512/256');
Result := TSHA2Hash_512_256(LastBufferSHA2(InitialSHA2_512mod,PAnsiChar(EvalStr)^,Length(EvalStr) * SizeOf(AnsiChar)));
end;

//==============================================================================
//------------------------------------------------------------------------------
//==============================================================================

Function SHA2ToStr_32(Hash: TSHA2Hash_32; Bits: Integer): String;
begin
Result := Copy(IntToHex(Hash.PartA,8) + IntToHex(Hash.PartB,8) +
               IntToHex(Hash.PartC,8) + IntToHex(Hash.PartD,8) +
               IntToHex(Hash.PartE,8) + IntToHex(Hash.PartF,8) +
               IntToHex(Hash.PartG,8) + IntToHex(Hash.PartH,8),1,Bits shr 2);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr_64(Hash: TSHA2Hash_64; Bits: Integer): String;
begin
Result := Copy(IntToHex(Hash.PartA,16) + IntToHex(Hash.PartB,16) +
               IntToHex(Hash.PartC,16) + IntToHex(Hash.PartD,16) +
               IntToHex(Hash.PartE,16) + IntToHex(Hash.PartF,16) +
               IntToHex(Hash.PartG,16) + IntToHex(Hash.PartH,16),1,Bits shr 2);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash_224): String;
begin
Result := SHA2ToStr_32(TSHA2Hash_32(Hash),224);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash_256): String;
begin
Result := SHA2ToStr_32(TSHA2Hash_32(Hash),256);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash_384): String;
begin
Result := SHA2ToStr_64(TSHA2Hash_64(Hash),384);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash_512): String;
begin
Result := SHA2ToStr_64(TSHA2Hash_64(Hash),512);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash_512_224): String;
begin
Result := SHA2ToStr_64(TSHA2Hash_64(Hash),224);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash_512_256): String;
begin
Result := SHA2ToStr_64(TSHA2Hash_64(Hash),256);
end;

//------------------------------------------------------------------------------

Function SHA2ToStr(Hash: TSHA2Hash): String;
begin
case Hash.HashSize of
  sha224:     Result := SHA2ToStr(Hash.Hash224);
  sha256:     Result := SHA2ToStr(Hash.Hash256);
  sha384:     Result := SHA2ToStr(Hash.Hash384);
  sha512:     Result := SHA2ToStr(Hash.Hash512);
  sha512_224: Result := SHA2ToStr(Hash.Hash512_224);
  sha512_256: Result := SHA2ToStr(Hash.Hash512_256);
else
  raise Exception.CreateFmt('SHA2ToStr: Unknown hash size (%d)',[Ord(Hash.HashSize)]);
end;
end;

//==============================================================================

{$IFDEF FPCDWM}{$PUSH}W5092{$ENDIF}
Function StrToSHA2_32(Str: String; Bits: Integer): TSHA2Hash_32;
var
  Characters: Integer;
  HashWords:  array[0..7] of UInt32 absolute Result;
  i:          Integer;
begin
Characters := Bits shr 2;
If Length(Str) < Characters then
  Str := StringOfChar('0',Characters - Length(Str)) + Str
else
  If Length(Str) > Characters then
    Str := Copy(Str,Length(Str) - Characters + 1,Characters);
Str := Str + StringOfChar('0',64 - Length(Str));
For i := 0 to 7 do
  HashWords[i] := UInt32(StrToInt('$' + Copy(Str,(i * 8) + 1,8)));
end;
{$IFDEF FPCDWM}{$POP}{$ENDIF}

//------------------------------------------------------------------------------

{$IFDEF FPCDWM}{$PUSH}W5092{$ENDIF}
Function StrToSHA2_64(Str: String; Bits: Integer): TSHA2Hash_64;
var
  Characters: Integer;
  HashWords:  array[0..7] of UInt64 absolute Result;
  i:          Integer;
begin
Characters := Bits shr 2;
If Length(Str) < Characters then
  Str := StringOfChar('0',Characters - Length(Str)) + Str
else
  If Length(Str) > Characters then
    Str := Copy(Str,Length(Str) - Characters + 1,Characters);
Str := Str + StringOfChar('0',128 - Length(Str));
For i := 0 to 7 do
  HashWords[i] := UInt64(StrToInt64('$' + Copy(Str,(i * 16) + 1,16)));
end;
{$IFDEF FPCDWM}{$POP}{$ENDIF}

//------------------------------------------------------------------------------

Function StrToSHA2_224(Str: String): TSHA2Hash_224;
begin
Result := TSHA2Hash_224(StrToSHA2_32(Str,224));
end;

//------------------------------------------------------------------------------

Function StrToSHA2_256(Str: String): TSHA2Hash_256;
begin
Result := TSHA2Hash_256(StrToSHA2_32(Str,256));
end;

//------------------------------------------------------------------------------

Function StrToSHA2_384(Str: String): TSHA2Hash_384;
begin
Result := TSHA2Hash_384(StrToSHA2_64(Str,384));
end;

//------------------------------------------------------------------------------

Function StrToSHA2_512(Str: String): TSHA2Hash_512;
begin
Result := TSHA2Hash_512(StrToSHA2_64(Str,512));
end;

//------------------------------------------------------------------------------

Function StrToSHA2_512_224(Str: String): TSHA2Hash_512_224;
begin
Result := TSHA2Hash_512_224(StrToSHA2_64(Str,224));
end;

//------------------------------------------------------------------------------

Function StrToSHA2_512_256(Str: String): TSHA2Hash_512_256;
begin
Result := TSHA2Hash_512_256(StrToSHA2_64(Str,256));
end;

//------------------------------------------------------------------------------

Function StrToSHA2(HashSize: TSHA2HashSize; Str: String): TSHA2Hash;
begin
Result.HashSize := HashSize;
case HashSize of
  sha224:     Result.Hash224 := StrToSHA2_224(Str);
  sha256:     Result.Hash256 := StrToSHA2_256(Str);
  sha384:     Result.Hash384 := StrToSHA2_384(Str);
  sha512:     Result.Hash512 := StrToSHA2_512(Str);
  sha512_224: Result.Hash512_224 := StrToSHA2_512_224(Str);
  sha512_256: Result.Hash512_256 := StrToSHA2_512_256(Str);
else
  raise Exception.CreateFmt('StrToSHA2: Unknown hash size (%d)',[Ord(HashSize)]);
end;
end;

//==============================================================================

Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_224): Boolean;
begin
try
  Hash := StrToSHA2_224(Str);
  Result := True;
except
  Result := False;
end;
end;

//------------------------------------------------------------------------------

Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_256): Boolean;
begin
try
  Hash := StrToSHA2_256(Str);
  Result := True;
except
  Result := False;
end;
end;
//------------------------------------------------------------------------------

Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_384): Boolean;
begin
try
  Hash := StrToSHA2_384(Str);
  Result := True;
except
  Result := False;
end;
end;
//------------------------------------------------------------------------------

Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_512): Boolean;
begin
try
  Hash := StrToSHA2_512(Str);
  Result := True;
except
  Result := False;
end;
end;

//------------------------------------------------------------------------------

Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_512_224): Boolean;
begin
try
  Hash := StrToSHA2_512_224(Str);
  Result := True;
except
  Result := False;
end;
end;

//------------------------------------------------------------------------------

Function TryStrToSHA2(const Str: String; out Hash: TSHA2Hash_512_256): Boolean;
begin
try
  Hash := StrToSHA2_512_256(Str);
  Result := True;
except
  Result := False;
end;
end;

//------------------------------------------------------------------------------

Function TryStrToSHA2(HashSize: TSHA2HashSize; const Str: String; out Hash: TSHA2Hash): Boolean;
begin
case HashSize of
  sha224:     Result := TryStrToSHA2(Str,Hash.Hash224);
  sha256:     Result := TryStrToSHA2(Str,Hash.Hash256);
  sha384:     Result := TryStrToSHA2(Str,Hash.Hash384);
  sha512:     Result := TryStrToSHA2(Str,Hash.Hash512);
  sha512_224: Result := TryStrToSHA2(Str,Hash.Hash512_224);
  sha512_256: Result := TryStrToSHA2(Str,Hash.Hash512_256);
else
  raise Exception.CreateFmt('TryStrToSHA2: Unknown hash size (%d)',[Ord(HashSize)]);
end;
end;

//==============================================================================

Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_224): TSHA2Hash_224;
begin
If not TryStrToSHA2(Str,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_256): TSHA2Hash_256;
begin
If not TryStrToSHA2(Str,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_384): TSHA2Hash_384;
begin
If not TryStrToSHA2(Str,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_512): TSHA2Hash_512;
begin
If not TryStrToSHA2(Str,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_512_224): TSHA2Hash_512_224;
begin
If not TryStrToSHA2(Str,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function StrToSHA2Def(const Str: String; Default: TSHA2Hash_512_256): TSHA2Hash_512_256;
begin
If not TryStrToSHA2(Str,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function StrToSHA2Def(HashSize: TSHA2HashSize; const Str: String; Default: TSHA2Hash): TSHA2Hash;
begin
If HashSize = Default.HashSize then
  begin
    If not TryStrToSHA2(HashSize,Str,Result) then
      Result := Default;
  end
else raise Exception.CreateFmt('StrToSHA2Def: Requested hash size differs from hash size of default value (%d,%d)',[Ord(HashSize),Ord(Default.HashSize)]);
end;

//==============================================================================

Function CompareSHA2_32(A,B: TSHA2Hash_32; Count: Integer): Integer;
var
  OverlayA: array[0..7] of UInt32 absolute A;
  OverlayB: array[0..7] of UInt32 absolute B;
  i:        Integer;
begin
Result := 0;
For i := 0 to Pred(Count) do
  If OverlayA[i] > OverlayB[i] then
    begin
      Result := -1;
      Break;
    end
  else If OverlayA[i] < OverlayB[i] then
    begin
      Result := -1;
      Break;
    end;
end;

//------------------------------------------------------------------------------

Function CompareSHA2_64(A,B: TSHA2Hash_64; Count: Integer): Integer;
var
  OverlayA: array[0..7] of UInt64 absolute A;
  OverlayB: array[0..7] of UInt64 absolute B;
  i:        Integer;

  Function CompareValues(ValueA,ValueB: UInt64): Integer;
  begin
    If Int64Rec(ValueA).Hi = Int64Rec(ValueB).Hi then
      begin
        If Int64Rec(ValueA).Lo > Int64Rec(ValueB).Lo then
          Result := -1
        else If Int64Rec(ValueA).Lo < Int64Rec(ValueB).Lo then
          Result := 1
        else
          Result := 0;
      end
    else If Int64Rec(ValueA).Hi > Int64Rec(ValueB).Hi then
      Result := -1
    else
      Result := 1;
  end;
  
begin
Result := 0;
For i := 0 to Pred(Count) do
  If CompareValues(OverlayA[i],OverlayB[i]) < 0 then
    begin
      Result := -1;
      Break;
    end
  else If CompareValues(OverlayA[i],OverlayB[i]) > 0 then
    begin
      Result := -1;
      Break;
    end;
end;

//------------------------------------------------------------------------------

Function CompareSHA2(A,B: TSHA2Hash_224): Integer;
begin
Result := CompareSHA2_32(TSHA2Hash_32(A),TSHA2Hash_32(B),7);
end;

//------------------------------------------------------------------------------

Function CompareSHA2(A,B: TSHA2Hash_256): Integer;
begin
Result := CompareSHA2_32(TSHA2Hash_32(A),TSHA2Hash_32(B),8);
end;

//------------------------------------------------------------------------------

Function CompareSHA2(A,B: TSHA2Hash_384): Integer;
begin
Result := CompareSHA2_64(TSHA2Hash_64(A),TSHA2Hash_64(B),6);
end;

//------------------------------------------------------------------------------

Function CompareSHA2(A,B: TSHA2Hash_512): Integer;
begin
Result := CompareSHA2_64(TSHA2Hash_64(A),TSHA2Hash_64(B),8);
end;

//------------------------------------------------------------------------------

Function CompareSHA2(A,B: TSHA2Hash_512_224): Integer;
begin
Result := CompareSHA2_64(TSHA2Hash_64(A),TSHA2Hash_64(B),3);
If Result = 0 then
  begin
    If Int64Rec(A.PartD).Hi < Int64Rec(B.PartD).Hi then
      Result := -1
    else If Int64Rec(A.PartD).Hi > Int64Rec(B.PartD).Hi then
      Result := 1;
  end;
end;

//------------------------------------------------------------------------------

Function CompareSHA2(A,B: TSHA2Hash_512_256): Integer;
begin
Result := CompareSHA2_64(TSHA2Hash_64(A),TSHA2Hash_64(B),4);
end;

//------------------------------------------------------------------------------

Function CompareSHA2(A,B: TSHA2Hash): Integer;
begin
If A.HashSize = B.HashSize then
  case A.HashSize of
    sha224:     Result := CompareSHA2(A.Hash224,B.Hash224);
    sha256:     Result := CompareSHA2(A.Hash256,B.Hash256);
    sha384:     Result := CompareSHA2(A.Hash384,B.Hash384);
    sha512:     Result := CompareSHA2(A.Hash512,B.Hash512);
    sha512_224: Result := CompareSHA2(A.Hash512_224,B.Hash512_224);
    sha512_256: Result := CompareSHA2(A.Hash512_256,B.Hash512_256);
  else
    raise Exception.CreateFmt('CompareSHA2: Unknown hash size (%d)',[Ord(A.HashSize)]);
  end
else raise Exception.Create('CompareSHA2: Cannot compare different hashes');
end;

//==============================================================================

Function SameSHA2(A,B: TSHA2Hash_224): Boolean;
begin
Result := (A.PartA = B.PartA) and (A.PartB = B.PartB) and
          (A.PartC = B.PartC) and (A.PartD = B.PartD) and
          (A.PartE = B.PartE) and (A.PartF = B.PartF) and
          (A.PartG = B.PartG);
end;

//------------------------------------------------------------------------------

Function SameSHA2(A,B: TSHA2Hash_256): Boolean;
begin
Result := (A.PartA = B.PartA) and (A.PartB = B.PartB) and
          (A.PartC = B.PartC) and (A.PartD = B.PartD) and
          (A.PartA = B.PartE) and (A.PartF = B.PartF) and
          (A.PartG = B.PartG) and (A.PartH = B.PartH);
end;

//------------------------------------------------------------------------------

Function SameSHA2(A,B: TSHA2Hash_384): Boolean;
begin
Result := (A.PartA = B.PartA) and (A.PartB = B.PartB) and
          (A.PartC = B.PartC) and (A.PartD = B.PartD) and
          (A.PartA = B.PartE) and (A.PartF = B.PartF);
end;

//------------------------------------------------------------------------------

Function SameSHA2(A,B: TSHA2Hash_512): Boolean;
begin
Result := (A.PartA = B.PartA) and (A.PartB = B.PartB) and
          (A.PartC = B.PartC) and (A.PartD = B.PartD) and
          (A.PartA = B.PartE) and (A.PartF = B.PartF) and
          (A.PartG = B.PartG) and (A.PartH = B.PartH);
end;

//------------------------------------------------------------------------------

Function SameSHA2(A,B: TSHA2Hash_512_224): Boolean;
begin
Result := (A.PartA = B.PartA) and (A.PartB = B.PartB) and
          (A.PartC = B.PartC) and (Int64Rec(A.PartD).Hi = Int64Rec(B.PartD).Hi);
end;

//------------------------------------------------------------------------------

Function SameSHA2(A,B: TSHA2Hash_512_256): Boolean;
begin
Result := (A.PartA = B.PartA) and (A.PartB = B.PartB) and
          (A.PartC = B.PartC) and (A.PartD = B.PartD);
end;

//------------------------------------------------------------------------------

Function SameSHA2(A,B: TSHA2Hash): Boolean;
begin
If A.HashSize = B.HashSize then
  case A.HashSize of
    sha224:     Result := SameSHA2(A.Hash224,B.Hash224);
    sha256:     Result := SameSHA2(A.Hash256,B.Hash256);
    sha384:     Result := SameSHA2(A.Hash384,B.Hash384);
    sha512:     Result := SameSHA2(A.Hash512,B.Hash512);
    sha512_224: Result := SameSHA2(A.Hash512_224,B.Hash512_224);
    sha512_256: Result := SameSHA2(A.Hash512_256,B.Hash512_256);
  else
    raise Exception.CreateFmt('SameSHA2: Unknown hash size (%d)',[Ord(A.HashSize)]);
  end
else Result := False;
end;

//==============================================================================

Function BinaryCorrectSHA2_32(Hash: TSHA2Hash_32): TSHA2Hash_32;
begin
Result.PartA := EndianSwap(Hash.PartA);
Result.PartB := EndianSwap(Hash.PartB);
Result.PartC := EndianSwap(Hash.PartC);
Result.PartD := EndianSwap(Hash.PartD);
Result.PartE := EndianSwap(Hash.PartE);
Result.PartF := EndianSwap(Hash.PartF);
Result.PartG := EndianSwap(Hash.PartG);
Result.PartH := EndianSwap(Hash.PartH);
end;

//------------------------------------------------------------------------------

Function BinaryCorrectSHA2_64(Hash: TSHA2Hash_64): TSHA2Hash_64;
begin
Result.PartA := EndianSwap(Hash.PartA);
Result.PartB := EndianSwap(Hash.PartB);
Result.PartC := EndianSwap(Hash.PartC);
Result.PartD := EndianSwap(Hash.PartD);
Result.PartE := EndianSwap(Hash.PartE);
Result.PartF := EndianSwap(Hash.PartF);
Result.PartG := EndianSwap(Hash.PartG);
Result.PartH := EndianSwap(Hash.PartH);
end;

//------------------------------------------------------------------------------

Function BinaryCorrectSHA2(Hash: TSHA2Hash_224): TSHA2Hash_224;
begin
Result := TSHA2Hash_224(BinaryCorrectSHA2_32(TSHA2Hash_32(Hash)));
end;

//------------------------------------------------------------------------------

Function BinaryCorrectSHA2(Hash: TSHA2Hash_256): TSHA2Hash_256;
begin
Result := TSHA2Hash_256(BinaryCorrectSHA2_32(TSHA2Hash_32(Hash)));
end;
 
//------------------------------------------------------------------------------

Function BinaryCorrectSHA2(Hash: TSHA2Hash_384): TSHA2Hash_384;
begin
Result := TSHA2Hash_384(BinaryCorrectSHA2_64(TSHA2Hash_64(Hash)));
end;
 
//------------------------------------------------------------------------------

Function BinaryCorrectSHA2(Hash: TSHA2Hash_512): TSHA2Hash_512;
begin
Result := TSHA2Hash_512(BinaryCorrectSHA2_64(TSHA2Hash_64(Hash)));
end;
 
//------------------------------------------------------------------------------

Function BinaryCorrectSHA2(Hash: TSHA2Hash_512_224): TSHA2Hash_512_224;
begin
Result := TSHA2Hash_512_224(BinaryCorrectSHA2_64(TSHA2Hash_64(Hash)));
end;
 
//------------------------------------------------------------------------------

Function BinaryCorrectSHA2(Hash: TSHA2Hash_512_256): TSHA2Hash_512_256;
begin
Result := TSHA2Hash_512_256(BinaryCorrectSHA2_64(TSHA2Hash_64(Hash)));
end;
 
//------------------------------------------------------------------------------

Function BinaryCorrectSHA2(Hash: TSHA2Hash): TSHA2Hash;
begin
case Hash.HashSize of
  sha224:     Result.Hash224 := BinaryCorrectSHA2(Hash.Hash224);
  sha256:     Result.Hash256 := BinaryCorrectSHA2(Hash.Hash256);
  sha384:     Result.Hash384 := BinaryCorrectSHA2(Hash.Hash384);
  sha512:     Result.Hash512 := BinaryCorrectSHA2(Hash.Hash512);
  sha512_224: Result.Hash512_224 := BinaryCorrectSHA2(Hash.Hash512_224);
  sha512_256: Result.Hash512_256 := BinaryCorrectSHA2(Hash.Hash512_256);
else
  raise Exception.CreateFmt('BinaryCorrectSHA2: Unknown hash size (%d)',[Ord(Hash.HashSize)]);
end;
end;

//==============================================================================
//------------------------------------------------------------------------------
//==============================================================================

procedure BufferSHA2_32(var Hash: TSHA2Hash_32; const Buffer; Size: TMemSize);
var
  i:    TMemSize;
  Buff: PBlockBuffer_32;
begin
If Size > 0 then
  begin
    If (Size mod BlockSize_32) = 0 then
      begin
        Buff := @Buffer;
        For i := 0 to Pred(Size div BlockSize_32) do
          begin
            Hash := BlockHash_32(Hash,Buff^);
            Inc(Buff);
          end;
      end
    else raise Exception.CreateFmt('BufferSHA2_32: Buffer size is not divisible by %d.',[BlockSize_32]);
  end;
end;

//------------------------------------------------------------------------------

procedure BufferSHA2_64(var Hash: TSHA2Hash_64; const Buffer; Size: TMemSize);
var
  i:    TMemSize;
  Buff: PBlockBuffer_64;
begin
If Size > 0 then
  begin
    If (Size mod BlockSize_64) = 0 then
      begin
        Buff := @Buffer;
        For i := 0 to Pred(Size div BlockSize_64) do
          begin
            Hash := BlockHash_64(Hash,Buff^);
            Inc(Buff);
          end;
      end
    else raise Exception.CreateFmt('BufferSHA2_64: Buffer size is not divisible by %d.',[BlockSize_32]);
  end;
end;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash_224; const Buffer; Size: TMemSize);
begin
BufferSHA2_32(TSHA2Hash_32(Hash),Buffer,Size);
end;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash_256; const Buffer; Size: TMemSize);
begin
BufferSHA2_32(TSHA2Hash_32(Hash),Buffer,Size);
end;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash_384; const Buffer; Size: TMemSize);
begin
BufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size);
end;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash_512; const Buffer; Size: TMemSize);
begin
BufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size);
end;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize);
begin
BufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size);
end;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize);
begin
BufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size);
end;

//------------------------------------------------------------------------------

procedure BufferSHA2(var Hash: TSHA2Hash; const Buffer; Size: TMemSize);
begin
case Hash.HashSize of
  sha224:     BufferSHA2(Hash.Hash224,Buffer,Size);
  sha256:     BufferSHA2(Hash.Hash256,Buffer,Size);
  sha384:     BufferSHA2(Hash.Hash384,Buffer,Size);
  sha512:     BufferSHA2(Hash.Hash512,Buffer,Size);
  sha512_224: BufferSHA2(Hash.Hash512_224,Buffer,Size);
  sha512_256: BufferSHA2(Hash.Hash512_256,Buffer,Size);
else
  raise Exception.CreateFmt('BufferSHA2: Unknown hash size (%d)',[Ord(Hash.HashSize)]);
end;
end;

//==============================================================================

Function LastBufferSHA2_32(Hash: TSHA2Hash_32; const Buffer; Size: TMemSize; MessageLength: UInt64): TSHA2Hash_32;
var
  FullBlocks:     TMemSize;
  LastBlockSize:  TMemSize;
  HelpBlocks:     TMemSize;
  HelpBlocksBuff: Pointer;
begin
Result := Hash;
FullBlocks := Size div BlockSize_32;
If FullBlocks > 0 then BufferSHA2_32(Result,Buffer,FullBlocks * BlockSize_32);
LastBlockSize := Size - (UInt64(FullBlocks) * BlockSize_32);
HelpBlocks := Ceil((LastBlockSize + SizeOf(UInt64) + 1) / BlockSize_32);
HelpBlocksBuff := AllocMem(HelpBlocks * BlockSize_32);
try
{$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
  Move(Pointer(PtrUInt(@Buffer) + (FullBlocks * BlockSize_32))^,HelpBlocksBuff^,LastBlockSize);
  PUInt8(PtrUInt(HelpBlocksBuff) + LastBlockSize)^ := $80;
  PUInt64(PtrUInt(HelpBlocksBuff) + (UInt64(HelpBlocks) * BlockSize_32) - SizeOf(UInt64))^ := EndianSwap(MessageLength);
{$IFDEF FPCDWM}{$POP}{$ENDIF}
  BufferSHA2_32(Result,HelpBlocksBuff^,HelpBlocks * BlockSize_32);
finally
  FreeMem(HelpBlocksBuff,HelpBlocks * BlockSize_32);
end;
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2_64(Hash: TSHA2Hash_64; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_64;
var
  FullBlocks:     TMemSize;
  LastBlockSize:  TMemSize;
  HelpBlocks:     TMemSize;
  HelpBlocksBuff: Pointer;
begin
Result := Hash;
FullBlocks := Size div BlockSize_64;
If FullBlocks > 0 then BufferSHA2_64(Result,Buffer,FullBlocks * BlockSize_64);
LastBlockSize := Size - (UInt64(FullBlocks) * BlockSize_64);
HelpBlocks := Ceil((LastBlockSize + SizeOf(OctaWord) + 1) / BlockSize_64);
HelpBlocksBuff := AllocMem(HelpBlocks * BlockSize_64);
try
{$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
  Move(Pointer(PtrUInt(@Buffer) + (FullBlocks * BlockSize_64))^,HelpBlocksBuff^,LastBlockSize);
  PUInt8(PtrUInt(HelpBlocksBuff) + LastBlockSize)^ := $80;
  POctaWord(PtrUInt(HelpBlocksBuff) + (UInt64(HelpBlocks) * BlockSize_64) - SizeOf(OctaWord))^ := EndianSwap(MessageLength);
{$IFDEF FPCDWM}{$POP}{$ENDIF}
  BufferSHA2_64(Result,HelpBlocksBuff^,HelpBlocks * BlockSize_64);
finally
  FreeMem(HelpBlocksBuff,HelpBlocks * BlockSize_64);
end;
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_224; const Buffer; Size: TMemSize; MessageLength: UInt64): TSHA2Hash_224;
begin
Result := TSHA2Hash_224(LastBufferSHA2_32(TSHA2Hash_32(Hash),Buffer,Size,MessageLength));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_256; const Buffer; Size: TMemSize; MessageLength: UInt64): TSHA2Hash_256;
begin
Result := TSHA2Hash_256(LastBufferSHA2_32(TSHA2Hash_32(Hash),Buffer,Size,MessageLength));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_384;
begin
Result := TSHA2Hash_384(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,MessageLength));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_512;
begin
Result := TSHA2Hash_512(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,MessageLength));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_512_224;
begin
Result := TSHA2Hash_512_224(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,MessageLength));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash_512_256;
begin
Result := TSHA2Hash_512_256(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,MessageLength));
end;

//==============================================================================

Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_384;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,0));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_512;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,0));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_512_224;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,0));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize; MessageLengthLo: UInt64): TSHA2Hash_512_256;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,0));
end;

//==============================================================================

Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_384;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_512;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_512_224;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash_512_256;
begin
Result := LastBufferSHA2(Hash,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
end;

//==============================================================================

Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize; MessageLength: UInt64): TSHA2Hash;
begin
Result.HashSize := Hash.HashSize;
case Hash.HashSize of
  sha224:     Result.Hash224 := LastBufferSHA2(Hash.Hash224,Buffer,Size,MessageLength);
  sha256:     Result.Hash256 := LastBufferSHA2(Hash.Hash256,Buffer,Size,MessageLength);
  sha384:     Result.Hash384 := LastBufferSHA2(Hash.Hash384,Buffer,Size,BuildOctaWord(MessageLength,0));
  sha512:     Result.Hash512 := LastBufferSHA2(Hash.Hash512,Buffer,Size,BuildOctaWord(MessageLength,0));
  sha512_224: Result.Hash512_224 := LastBufferSHA2(Hash.Hash512_224,Buffer,Size,BuildOctaWord(MessageLength,0));
  sha512_256: Result.Hash512_256 := LastBufferSHA2(Hash.Hash512_256,Buffer,Size,BuildOctaWord(MessageLength,0));
else
  raise Exception.CreateFmt('LastBufferSHA2: Unknown hash size (%d)',[Ord(Hash.HashSize)]);
end;
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize; MessageLengthLo, MessageLengthHi: UInt64): TSHA2Hash;
begin
Result.HashSize := Hash.HashSize;
case Hash.HashSize of
  sha224:     Result.Hash224 := LastBufferSHA2(Hash.Hash224,Buffer,Size,MessageLengthLo);
  sha256:     Result.Hash256 := LastBufferSHA2(Hash.Hash256,Buffer,Size,MessageLengthLo);
  sha384:     Result.Hash384 := LastBufferSHA2(Hash.Hash384,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
  sha512:     Result.Hash512 := LastBufferSHA2(Hash.Hash512,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
  sha512_224: Result.Hash512_224 := LastBufferSHA2(Hash.Hash512_224,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
  sha512_256: Result.Hash512_256 := LastBufferSHA2(Hash.Hash512_256,Buffer,Size,BuildOctaWord(MessageLengthLo,MessageLengthHi));
else
  raise Exception.CreateFmt('LastBufferSHA2: Unknown hash size (%d)',[Ord(Hash.HashSize)]);
end;
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize; MessageLength: OctaWord): TSHA2Hash;
begin
Result.HashSize := Hash.HashSize;
case Hash.HashSize of
  sha224:     Result.Hash224 := LastBufferSHA2(Hash.Hash224,Buffer,Size,MessageLength.Lo);
  sha256:     Result.Hash256 := LastBufferSHA2(Hash.Hash256,Buffer,Size,MessageLength.Lo);
  sha384:     Result.Hash384 := LastBufferSHA2(Hash.Hash384,Buffer,Size,MessageLength);
  sha512:     Result.Hash512 := LastBufferSHA2(Hash.Hash512,Buffer,Size,MessageLength);
  sha512_224: Result.Hash512_224 := LastBufferSHA2(Hash.Hash512_224,Buffer,Size,MessageLength);
  sha512_256: Result.Hash512_256 := LastBufferSHA2(Hash.Hash512_256,Buffer,Size,MessageLength);
else
  raise Exception.CreateFmt('LastBufferSHA2: Unknown hash size (%d)',[Ord(Hash.HashSize)]);
end;
end;

//==============================================================================

Function LastBufferSHA2(Hash: TSHA2Hash_224; const Buffer; Size: TMemSize): TSHA2Hash_224;
begin
Result := TSHA2Hash_224(LastBufferSHA2_32(TSHA2Hash_32(Hash),Buffer,Size,UInt64(Size) shl 3));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_256; const Buffer; Size: TMemSize): TSHA2Hash_256;
begin
Result := TSHA2Hash_256(LastBufferSHA2_32(TSHA2Hash_32(Hash),Buffer,Size,UInt64(Size) shl 3));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_384; const Buffer; Size: TMemSize): TSHA2Hash_384;
begin
Result := TSHA2Hash_384(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,SizeToMessageLength(Size)));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512; const Buffer; Size: TMemSize): TSHA2Hash_512;
begin
Result := TSHA2Hash_512(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,SizeToMessageLength(Size)));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_224; const Buffer; Size: TMemSize): TSHA2Hash_512_224;
begin
Result := TSHA2Hash_512_224(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,SizeToMessageLength(Size)));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash_512_256; const Buffer; Size: TMemSize): TSHA2Hash_512_256;
begin
Result := TSHA2Hash_512_256(LastBufferSHA2_64(TSHA2Hash_64(Hash),Buffer,Size,SizeToMessageLength(Size)));
end;

//------------------------------------------------------------------------------

Function LastBufferSHA2(Hash: TSHA2Hash; const Buffer; Size: TMemSize): TSHA2Hash;
begin
Result.HashSize := Hash.HashSize;
case Hash.HashSize of
  sha224:     Result.Hash224 := LastBufferSHA2(Hash.Hash224,Buffer,Size);
  sha256:     Result.Hash256 := LastBufferSHA2(Hash.Hash256,Buffer,Size);
  sha384:     Result.Hash384 := LastBufferSHA2(Hash.Hash384,Buffer,Size);
  sha512:     Result.Hash512 := LastBufferSHA2(Hash.Hash512,Buffer,Size);
  sha512_224: Result.Hash512_224 := LastBufferSHA2(Hash.Hash512_224,Buffer,Size);
  sha512_256: Result.Hash512_256 := LastBufferSHA2(Hash.Hash512_256,Buffer,Size);
else
  raise Exception.CreateFmt('LastBufferSHA2: Unknown hash size (%d)',[Ord(Hash.HashSize)]);
end;
end;

//==============================================================================
//------------------------------------------------------------------------------
//==============================================================================

Function BufferSHA2(HashSize: TSHA2HashSize; const Buffer; Size: TMemSize): TSHA2Hash;
begin
Result.HashSize := HashSize;
case HashSize of
  sha224:     Result.Hash224 := LastBufferSHA2(InitialSHA2_224,Buffer,Size);
  sha256:     Result.Hash256 := LastBufferSHA2(InitialSHA2_256,Buffer,Size);
  sha384:     Result.Hash384 := LastBufferSHA2(InitialSHA2_384,Buffer,Size);
  sha512:     Result.Hash512 := LastBufferSHA2(InitialSHA2_512,Buffer,Size);
  sha512_224: Result.Hash512_224 := LastBufferSHA2(InitialSHA2_512_224,Buffer,Size);
  sha512_256: Result.Hash512_256 := LastBufferSHA2(InitialSHA2_512_256,Buffer,Size);
else
  raise Exception.CreateFmt('BufferSHA2: Unknown hash size (%d)',[Ord(HashSize)]);
end;
end;

//==============================================================================

Function AnsiStringSHA2(HashSize: TSHA2HashSize; const Str: AnsiString): TSHA2Hash;
begin
Result := BufferSHA2(HashSize,PAnsiChar(Str)^,Length(Str) * SizeOf(AnsiChar));
end;

//------------------------------------------------------------------------------

Function WideStringSHA2(HashSize: TSHA2HashSize; const Str: WideString): TSHA2Hash;
begin
Result := BufferSHA2(HashSize,PWideChar(Str)^,Length(Str) * SizeOf(WideChar));
end;

//------------------------------------------------------------------------------

Function StringSHA2(HashSize: TSHA2HashSize; const Str: String): TSHA2Hash;
begin
Result := BufferSHA2(HashSize,PChar(Str)^,Length(Str) * SizeOf(Char));
end;

//==============================================================================

Function StreamSHA2(HashSize: TSHA2HashSize; Stream: TStream; Count: Int64 = -1): TSHA2Hash;
var
  Buffer:         Pointer;
  BytesRead:      TMemSize;
  MessageLength:  OctaWord;
begin
If Assigned(Stream) then
  begin
    If Count = 0 then
      Count := Stream.Size - Stream.Position;
    If Count < 0 then
      begin
        Stream.Position := 0;
        Count := Stream.Size;
      end;
    MessageLength := SizeToMessageLength(UInt64(Count));
    GetMem(Buffer,BufferSize);
    try
      Result.HashSize := HashSize;
      case HashSize of
        sha224:     Result.Hash224 := InitialSHA2_224;
        sha256:     Result.Hash256 := InitialSHA2_256;
        sha384:     Result.Hash384 := InitialSHA2_384;
        sha512:     Result.Hash512 := InitialSHA2_512;
        sha512_224: Result.Hash512_224 := InitialSHA2_512_224;
        sha512_256: Result.Hash512_256 := InitialSHA2_512_256;
      else
        raise Exception.CreateFmt('StreamSHA2: Unknown hash size (%d)',[Ord(HashSize)]);
      end;
      repeat
        BytesRead := Stream.Read(Buffer^,Min(BufferSize,Count));
        If BytesRead < BufferSize then
          Result := LastBufferSHA2(Result,Buffer^,BytesRead,MessageLength)
        else
          BufferSHA2(Result,Buffer^,BytesRead);
        Dec(Count,BytesRead);
      until BytesRead < BufferSize;
    finally
      FreeMem(Buffer,BufferSize);
    end;
  end
else raise Exception.Create('StreamSHA2: Stream is not assigned.');
end;

//------------------------------------------------------------------------------

Function FileSHA2(HashSize: TSHA2HashSize; const FileName: String): TSHA2Hash;
var
  FileStream: TFileStream;
begin
FileStream := TFileStream.Create(StrToRTL(FileName), fmOpenRead or fmShareDenyWrite);
try
  Result := StreamSHA2(HashSize,FileStream);
finally
  FileStream.Free;
end;
end;

//==============================================================================
//------------------------------------------------------------------------------
//==============================================================================

Function SHA2_Init(HashSize: TSHA2HashSize): TSHA2Context;
begin
Result := AllocMem(SizeOf(TSHA2Context_Internal));
with PSHA2Context_Internal(Result)^ do
  begin
    MessageHash.HashSize := HashSize;
    case HashSize of
      sha224:     MessageHash.Hash224 := InitialSHA2_224;
      sha256:     MessageHash.Hash256 := InitialSHA2_256;
      sha384:     MessageHash.Hash384 := InitialSHA2_384;
      sha512:     MessageHash.Hash512 := InitialSHA2_512;
      sha512_224: MessageHash.Hash512_224 := InitialSHA2_512_224;
      sha512_256: MessageHash.Hash512_256 := InitialSHA2_512_256;
    else
      raise Exception.CreateFmt('SHA2_Hash: Unknown hash size (%d)',[Ord(HashSize)]);
    end;
    If HashSize in [sha224,sha256] then
      ActiveBlockSize := BlockSize_32
    else
      ActiveBlockSize := BlockSize_64;
    MessageLength := ZeroOctaWord;
    TransferSize := 0;
  end;
end;

//------------------------------------------------------------------------------

procedure SHA2_Update(Context: TSHA2Context; const Buffer; Size: TMemSize);
var
  FullBlocks:     TMemSize;
  RemainingSize:  TMemSize;
begin
with PSHA2Context_Internal(Context)^ do
  begin
    If TransferSize > 0 then
      begin
        If Size >= (ActiveBlockSize - TransferSize) then
          begin
            IncOctaWord(MessageLength,SizeToMessageLength(ActiveBlockSize - TransferSize));
            Move(Buffer,TransferBuffer[TransferSize],ActiveBlockSize - TransferSize);
            BufferSHA2(MessageHash,TransferBuffer,ActiveBlockSize);
            RemainingSize := Size - (ActiveBlockSize - TransferSize);
            TransferSize := 0;
          {$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
            SHA2_Update(Context,Pointer(PtrUInt(@Buffer) + (Size - RemainingSize))^,RemainingSize);
          {$IFDEF FPCDWM}{$POP}{$ENDIF}
          end
        else
          begin
            IncOctaWord(MessageLength,SizeToMessageLength(Size));
            Move(Buffer,TransferBuffer[TransferSize],Size);
            Inc(TransferSize,Size);
          end;  
      end
    else
      begin
        IncOctaWord(MessageLength,SizeToMessageLength(Size));
        FullBlocks := Size div ActiveBlockSize;
        BufferSHA2(MessageHash,Buffer,FullBlocks * ActiveBlockSize);
        If (FullBlocks * ActiveBlockSize) < Size then
          begin
            TransferSize := Size - (UInt64(FullBlocks) * ActiveBlockSize);
          {$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
            Move(Pointer(PtrUInt(@Buffer) + (Size - TransferSize))^,TransferBuffer,TransferSize);
          {$IFDEF FPCDWM}{$POP}{$ENDIF}
          end;
      end;
  end;
end;

//------------------------------------------------------------------------------

Function SHA2_Final(var Context: TSHA2Context; const Buffer; Size: TMemSize): TSHA2Hash;
begin
SHA2_Update(Context,Buffer,Size);
Result := SHA2_Final(Context);
end;

//------------------------------------------------------------------------------

Function SHA2_Final(var Context: TSHA2Context): TSHA2Hash;
begin
with PSHA2Context_Internal(Context)^ do
  Result := LastBufferSHA2(MessageHash,TransferBuffer,TransferSize,MessageLength);
FreeMem(Context,SizeOf(TSHA2Context_Internal));
Context := nil;
end;

//------------------------------------------------------------------------------

Function SHA2_Hash(HashSize: TSHA2HashSize; const Buffer; Size: TMemSize): TSHA2Hash;
begin
Result.HashSize := HashSize;
case HashSize of
  sha224:     Result.Hash224 := InitialSHA2_224;
  sha256:     Result.Hash256 := InitialSHA2_256;
  sha384:     Result.Hash384 := InitialSHA2_384;
  sha512:     Result.Hash512 := InitialSHA2_512;
  sha512_224: Result.Hash512_224 := InitialSHA2_512_224;
  sha512_256: Result.Hash512_256 := InitialSHA2_512_256;
else
  raise Exception.CreateFmt('SHA2_Hash: Unknown hash size (%d)',[Ord(HashSize)]);
end;
Result := LastBufferSHA2(Result,Buffer,Size,SizeToMessageLength(Size));
end;

end.
