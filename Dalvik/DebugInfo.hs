{-# LANGUAGE ViewPatterns #-}
module Dalvik.DebugInfo
  ( emptyDebugState
  , executeDebugInsns
  ) where

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
  , dbgSeqNo         = 0
  }

emptyDebugState :: DebugState
emptyDebugState =
  DebugState
  { dbgAddr          = 0
  , dbgLine          = 0
  , dbgSourceFile    = -1
  , dbgPrologueEnd   = False
  , dbgEpilogueBegin = False
  , dbgLocals        = Map.empty
  , dbgPositions     = []
  , dbgSeqNo         = 0
  }

dbgLineBase, dbgLineRange :: Word32
dbgLineBase = -4
dbgLineRange = 15

startLocal :: DebugState -> Word32 -> Int32 -> Int32 -> Int32
           -> DebugState
startLocal s r nid tid sid =
  s { dbgLocals = Map.alter start r (dbgLocals s)
    , dbgSeqNo = n + 1
    }
  where start (Just (LocalInfo 0 a' 0xFFFFFFFF nid' tid' sid' : ls))  =
            Just $ l' : LocalInfo n a' a nid' tid' sid' : ls
        start (Just ls) = Just $ l' : ls
        start Nothing = Just [l']
        a = dbgAddr s
        n = dbgSeqNo s
        l' = LocalInfo 0 a 0xFFFFFFFF nid tid sid

endLocal :: DebugState -> Word32 -> DebugState
endLocal s r =
  s { dbgLocals = Map.alter fixupEnd r (dbgLocals s)
    , dbgSeqNo = n + 1
    }
  where fixupEnd (Just (LocalInfo _ a _ nid tid sid : ls)) =
          Just $ LocalInfo n a (dbgAddr s) nid tid sid : ls
        fixupEnd _ =
          Just [LocalInfo n 0 (dbgAddr s) (-1) (-1) (-1)]
        n = dbgSeqNo s

restartLocal :: DebugState -> Word32 -> DebugState
restartLocal s r =
  case Map.findWithDefault [] r (dbgLocals s) of
    (LocalInfo _ _ _ nid tid sid : _) -> startLocal s r nid tid sid
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
      where adjOpcode =
              fromIntegral $
              fromIntegral op - fromEnum DBG_FIRST_SPECIAL
            line' = dbgLine s + dbgLineBase + (adjOpcode `mod` dbgLineRange)
            addr' = dbgAddr s + (adjOpcode `div` dbgLineRange)
            p = PositionInfo addr' line'

executeDebugInsns :: DexFile
                  -> CodeItem
                  -> AccessFlags
                  -> MethodId
                  -> Either String DebugState
executeDebugInsns _ (codeDebugInfo -> Nothing) _ _ =
  return emptyDebugState
executeDebugInsns dex code@(codeDebugInfo -> Just info) flags mid = do
  let toEither str a = maybe (Left str) Right a
  meth <- toEither ("Unknown method ID " ++ show mid) (getMethod dex mid)
  proto <- toEither ("No parameter types") (getProto dex (methProtoId meth))
  let paramTypes = protoParams proto
      thisType = methClassId meth
  cls <- toEither ("Class of method not found") (getClass dex thisType)
  let is _ [] = dbgByteCodes info
      is r ((n, t) : rest) =
        StartLocal r n (fromIntegral t) : is (r + pregs t) rest
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
      srcFile = fromIntegral . classSourceNameId $ cls
  return $
    finishLocals lastAddr $
    foldl' executeInsn (initialDebugState info srcFile) (is reg0 params)
executeDebugInsns _ _ _ _ =
  Left "This should never happen (executeDebugInsns fallthrough)."

finishLocals :: Word32 -> DebugState -> DebugState
finishLocals lastAddr s =
  s { dbgLocals = Map.map (map updLocal) (dbgLocals s) }
    where updLocal (LocalInfo _ a 0xFFFFFFFF nid tid sid) =
            LocalInfo (dbgSeqNo s) a (lastAddr + 1) nid tid sid
          updLocal l = l
