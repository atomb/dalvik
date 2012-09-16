{-# LANGUAGE OverloadedStrings #-}
module Dalvik.AccessFlags
  ( AccessFlag(..)
  , AccessFlags
  , AccessType(..)
  , flagCode
  , codeFlag
  , flagString
  , flagsString
  , hasAccessFlag
  ) where

import Data.Bits
import Data.List
import Data.Monoid
import Data.String
import Data.Word
import Text.Printf

type AccessFlags = Word32

data AccessFlag
  = ACC_PUBLIC
  | ACC_PRIVATE
  | ACC_PROTECTED
  | ACC_STATIC
  | ACC_FINAL
  | ACC_SYNCHRONIZED
  | ACC_VOLATILE
  | ACC_BRIDGE
  | ACC_TRANSIENT
  | ACC_VARARGS
  | ACC_NATIVE
  | ACC_INTERFACE
  | ACC_ABSTRACT
  | ACC_STRICT
  | ACC_SYNTHETIC
  | ACC_ANNOTATION
  | ACC_ENUM
  | ACC_CONSTRUCTOR
  | ACC_DECLARED_SYNCHRONIZED
    deriving (Eq, Enum)

flagCode :: AccessFlag -> Word32
flagCode ACC_PUBLIC = 0x1
flagCode ACC_PRIVATE = 0x2
flagCode ACC_PROTECTED = 0x4
flagCode ACC_STATIC = 0x8
flagCode ACC_FINAL = 0x10
flagCode ACC_SYNCHRONIZED = 0x20
flagCode ACC_VOLATILE = 0x40
flagCode ACC_BRIDGE = 0x40
flagCode ACC_TRANSIENT = 0x80
flagCode ACC_VARARGS = 0x80
flagCode ACC_NATIVE = 0x100
flagCode ACC_INTERFACE = 0x200
flagCode ACC_ABSTRACT = 0x400
flagCode ACC_STRICT = 0x800
flagCode ACC_SYNTHETIC = 0x1000
flagCode ACC_ANNOTATION = 0x2000
flagCode ACC_ENUM = 0x4000
flagCode ACC_CONSTRUCTOR = 0x10000
flagCode ACC_DECLARED_SYNCHRONIZED = 0x20000

data AccessType = AClass | AField | AMethod deriving Eq

{-
tyString :: (IsString s) => AccessType -> s
tyString AClass = "class"
tyString AField = "field"
tyString AMethod = "method"
-}

codeFlag :: AccessType -> Word32 -> AccessFlag
codeFlag _       0x00001 = ACC_PUBLIC
codeFlag _       0x00002 = ACC_PRIVATE
codeFlag _       0x00004 = ACC_PROTECTED
codeFlag _       0x00008 = ACC_STATIC
codeFlag _       0x00010 = ACC_FINAL
codeFlag AMethod 0x00020 = ACC_SYNCHRONIZED
codeFlag AField  0x00040 = ACC_VOLATILE
codeFlag AMethod 0x00040 = ACC_BRIDGE
codeFlag AField  0x00080 = ACC_TRANSIENT
codeFlag AMethod 0x00080 = ACC_VARARGS
codeFlag AMethod 0x00100 = ACC_NATIVE
codeFlag AClass  0x00200 = ACC_INTERFACE
codeFlag AClass  0x00400 = ACC_ABSTRACT
codeFlag AMethod 0x00400 = ACC_ABSTRACT
codeFlag AMethod 0x00800 = ACC_STRICT
codeFlag _       0x01000 = ACC_SYNTHETIC
codeFlag AClass  0x02000 = ACC_ANNOTATION
codeFlag AClass  0x04000 = ACC_ENUM
codeFlag AField  0x04000 = ACC_ENUM
codeFlag AMethod 0x10000 = ACC_CONSTRUCTOR
codeFlag AMethod 0x20000 = ACC_DECLARED_SYNCHRONIZED
codeFlag _ bits = error $ printf "(unknown access flag %08x)" bits

flagString :: (IsString s) => AccessFlag -> s
flagString ACC_PUBLIC = "PUBLIC"
flagString ACC_PRIVATE = "PRIVATE"
flagString ACC_PROTECTED = "PROTECTED"
flagString ACC_STATIC = "STATIC"
flagString ACC_FINAL = "FINAL"
flagString ACC_SYNCHRONIZED = "SYNCHRONIZED"
flagString ACC_VOLATILE = "VOLATILE"
flagString ACC_BRIDGE = "BRIDGE"
flagString ACC_TRANSIENT = "TRANSIENT"
flagString ACC_VARARGS = "VARARGS"
flagString ACC_NATIVE = "NATIVE"
flagString ACC_INTERFACE = "INTERFACE"
flagString ACC_ABSTRACT = "ABSTRACT"
flagString ACC_STRICT = "STRICT"
flagString ACC_SYNTHETIC = "SYNTHETIC"
flagString ACC_ANNOTATION = "ANNOTATION"
flagString ACC_ENUM = "ENUM"
flagString ACC_CONSTRUCTOR = "CONSTRUCTOR"
flagString ACC_DECLARED_SYNCHRONIZED = "DECLARED_SYNCHRONIZED"

flagsString :: (IsString s, Monoid s) => AccessType -> Word32 -> s
flagsString ty w = mconcat $ intersperse " "
  [ flagString (codeFlag ty c) | c <- allCodes, w .&. c /= 0 ]
    where allCodes = [ 0x00001, 0x00002, 0x00004, 0x00008
                     , 0x00010, 0x00020, 0x00040, 0x00080
                     , 0x00100, 0x00200, 0x00400, 0x00800
                     , 0x01000, 0x02000, 0x04000
                     , 0x10000, 0x20000
                     ]

andTrue :: Word32 -> Word32 -> Bool
andTrue w1 w2 = (w1 .&. w2) /= 0

hasAccessFlag :: AccessFlag -> Word32 ->  Bool
hasAccessFlag f = andTrue (flagCode f)
