{-# LANGUAGE ParallelListComp #-}

module Dalvik.HexPrint where

import Blaze.ByteString.Builder
import Data.Bits
import Data.Monoid
import Data.Word

hexDigit :: Integral a => a -> Word8
hexDigit n
    | n <= 9    = fromIntegral n + 48
    | otherwise = fromIntegral n + 87
{-# INLINE hexDigit #-}

hexadecimal :: Integral a => a -> Builder
hexadecimal i
    | i < 0     = error msg
    | otherwise = fromWrite $ go i
  where
    go n | n < 16    = writeWord8 $! hexDigit n
         | otherwise = go (n `quot` 16) `mappend` (writeWord8 $! hexDigit (n `rem` 16))
    msg = "Dalvik.HexPrint.hexadecimal: applied to negative number"
{-# INLINE hexadecimal #-}

{-# SPECIALIZE fixedHex :: Int -> Word8 -> Builder #-}
{-# SPECIALIZE fixedHex :: Int -> Word16 -> Builder #-}
{-# SPECIALIZE fixedHex :: Int -> Word32 -> Builder #-}
{-# SPECIALIZE fixedHex :: Int -> Word64 -> Builder #-}
fixedHex :: (Integral a, Bits a) => Int -> a -> Builder
fixedHex digits i = fromWrite $ go digits i
  where
    go 0 _ = mempty
    go 1 n = writeWord8 $! hexDigit (n .&. 0xF)
    go d n = (writeWord8 $! hexDigit ((n .&. mask) `shiftR` shiftAmt)) `mappend`
             go (d - 1) n
               where mask = 0xF `shiftL` shiftAmt
                     shiftAmt = (d - 1) * 4
{-# INLINE fixedHex #-}
