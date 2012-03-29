module Dalvik.AccessFlags where

import Data.Bits
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

tyString :: AccessType -> String
tyString AClass = "class"
tyString AField = "field"
tyString AMethod = "method"

flagString :: AccessType -> AccessFlag -> String
flagString _ ACC_PUBLIC = "PUBLIC"
flagString _ ACC_PRIVATE = "PRIVATE"
flagString _ ACC_PROTECTED = "PROTECTED"
flagString _ ACC_STATIC = "STATIC"
flagString _ ACC_FINAL = "FINAL"
flagString AMethod ACC_SYNCHRONIZED = "SYNCHRONIZED"
flagString AField  ACC_VOLATILE = "VOLATILE"
flagString AMethod ACC_BRIDGE = "BRIDGE"
flagString AField  ACC_TRANSIENT = "TRANSIENT"
flagString AMethod ACC_VARARGS = "VARARGS"
flagString AMethod ACC_NATIVE = "NATIVE"
flagString AClass  ACC_INTERFACE = "INTERFACE"
flagString AClass ACC_ABSTRACT = "ABSTRACT"
flagString AMethod ACC_ABSTRACT = "ABSTRACT"
flagString AMethod ACC_STRICT = "STRICT"
flagString _ ACC_SYNTHETIC = "SYNTHETIC"
flagString AClass  ACC_ANNOTATION = "ANNOTATION"
flagString AClass ACC_ENUM = "ENUM"
flagString AField ACC_ENUM = "ENUM"
flagString AMethod ACC_CONSTRUCTOR = "CONSTRUCTOR"
flagString AMethod ACC_DECLARED_SYNCHRONIZED = "DECLARED_SYNCHRONIZED"
flagString ty f =
  printf "(unknown access flag %08x for %s)" (flagCode f) (tyString ty)

flagsString :: AccessType -> Word32 -> String
flagsString ty w =
  unwords [ flagString ty f | f <- allFlags, w .&. (flagCode f) /= 0 ]
    where allFlags = [ACC_PUBLIC .. ACC_DECLARED_SYNCHRONIZED]

andTrue :: Word32 -> Word32 -> Bool
andTrue w1 w2 = (w1 .&. w2) /= 0

hasAccessFlag :: AccessFlag -> Word32 ->  Bool
hasAccessFlag f w = andTrue (flagCode f) w
