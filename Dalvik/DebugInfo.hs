module Dalvik.DebugInfo (executeInsns) where

import qualified Data.ByteString.Char8 as CBS
import Data.Int
import Data.List
import qualified Data.Map as Map
import Data.Word

import Dalvik.AccessFlags
import Dalvik.Types

initialDebugState :: DebugInfo -> Int32 -> DebugState
initialDebugState info srcFile =
  DebugState
  { dbgAddr          = 0
  , dbgLine          = dbgLineStart info
  , dbgSourceFile    = srcFile
  , dbgPrologueEnd   = False
  , dbgEpilogueBegin = False
  , dbgLocals        = Map.empty
  , dbgPositions     = []
  }

dbgLineBase, dbgLineRange :: Word32
dbgLineBase = -4
dbgLineRange = 15

startLocal :: DebugState -> Word32 -> Int32 -> Int32 -> Int32
           -> DebugState
startLocal s r nid tid sid = s { dbgLocals = Map.alter start r (dbgLocals s) }
    where start (Just (LocalInfo a' 0xFFFFFFFF nid' tid' sid' : ls))  =
            Just $ l' : LocalInfo a' a nid' tid' sid' : ls
          start (Just ls) = Just $ l' : ls
          start Nothing = Just [l']
          a = dbgAddr s
          l' = LocalInfo a 0xFFFFFFFF nid tid sid

endLocal :: DebugState -> Word32 -> DebugState
endLocal s r = s { dbgLocals = Map.alter fixupEnd r (dbgLocals s) }
  where fixupEnd (Just (LocalInfo a _ nid tid sid : ls)) =
          Just $ LocalInfo a (dbgAddr s) nid tid sid : ls
        fixupEnd _ =
          Just [LocalInfo 0 (dbgAddr s) (-1) (-1) (-1)]

restartLocal :: DebugState -> Word32 -> DebugState
restartLocal s r =
  case Map.findWithDefault [] r (dbgLocals s) of
    (LocalInfo _ _ nid tid sid : _) -> startLocal s r nid tid sid
    [] -> startLocal s r (-1) (-1) (-1)

executeInsn :: DebugState -> DebugInstruction -> DebugState
executeInsn s i =
  case i of
    EndSequence -> s
    AdvancePC off -> s { dbgAddr = dbgAddr s + off }
    AdvanceLine off -> s { dbgLine = dbgLine s + fromIntegral off }
    StartLocal r nid tid -> startLocal s r nid tid (-1)
    StartLocalExt r nid tid sid -> startLocal s r nid tid sid
    EndLocal r -> endLocal s r
    RestartLocal r -> restartLocal s r
    SetPrologueEnd -> s { dbgPrologueEnd = True }
    SetEpilogueBegin -> s { dbgEpilogueBegin = True }
    SetFile sid -> s { dbgSourceFile = sid }
    SpecialAdjust op -> s { dbgAddr = addr'
                          , dbgLine = line'
                          , dbgPrologueEnd = False
                          , dbgEpilogueBegin = False
                          , dbgPositions = p : dbgPositions s
                          }
      where adjOpcode = fromIntegral $
                        fromIntegral op - fromEnum DBG_FIRST_SPECIAL
            line' = dbgLine s + dbgLineBase + (adjOpcode `mod` dbgLineRange)
            addr' = dbgAddr s + (adjOpcode `div` dbgLineRange)
            p = PositionInfo addr' line'

executeInsns :: DexFile
             -> CodeItem
             -> AccessFlags
             -> MethodId
             -> DebugState
executeInsns dex code flags mid =
  finishLocals lastAddr $
  foldl' executeInsn (initialDebugState info srcFile) (is reg0 params)
    where is _ [] = dbgByteCodes info
          is r ((n, t) : rest) =
            StartLocal r n (fromIntegral t) : is (r + pregs t) rest
          info = codeDebugInfo code
          hasThis = not $ hasAccessFlag ACC_STATIC flags
          reg0 = fromIntegral (codeRegs code) - sum (map pregs ptypes)
          pnames = (if hasThis then (thisNid :) else id)
                   (dbgParamNames info)
          ptypes = (if hasThis then (thisType :) else id) paramTypes
          params = zip pnames ptypes
          pregs tid =
            case CBS.unpack `fmap` getTypeName dex tid of
              Just "J" -> 2
              Just "D" -> 2
              _ -> 1
          thisNid = fromIntegral . dexThisId $ dex
          lastAddr = fromIntegral $ length (codeInsns code) - 1
          paramTypes = protoParams . getProto dex . methProtoId $ meth
          thisType = methClassId meth
          meth = getMethod dex mid
          srcFile = fromIntegral . classSourceNameId . getClass dex $ thisType

finishLocals :: Word32 -> DebugState -> DebugState
finishLocals lastAddr s =
  s { dbgLocals = Map.map (map updLocal) (dbgLocals s) }
    where updLocal (LocalInfo a 0xFFFFFFFF nid tid sid) =
            LocalInfo a (lastAddr + 1) nid tid sid
          updLocal l = l
