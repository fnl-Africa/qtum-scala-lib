package org.qtumproject.qtum.reference

import org.qtumproject.qtum.{BlockHeader, ByteVector32}
import org.scalatest.FunSuite

class PowSpec extends FunSuite {
  test("calculate next work required") {
    val header = BlockHeader(version = 2, hashPreviousBlock = ByteVector32.Zeroes,
      hashMerkleRoot = ByteVector32.Zeroes, time = 0L, bits = 0L, nonce = 0L,
      hashStateRoot = ByteVector32.Zeroes, hashUTXORoot = ByteVector32.Zeroes,
      prev_stake_hash = ByteVector32.Zeroes, prev_stake_n = 0L, sizeVchSig = 0, vchSig = Array())

    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1262152739, bits = 0x1d00ffff), 1261130161) === 0x1d00d86aL)
    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1233061996, bits = 0x1d00ffff), 1231006505) === 0x1d00ffffL)
    assert(BlockHeader.calculateNextWorkRequired(header.copy(time = 1279297671, bits = 0x1c05a3f4), 1279008237) === 0x1c0168fdL)
  }
}
