package org.qtumproject.qtum

import org.scalatest.FunSuite
import scodec.bits._

/**
  * Created by fabrice on 19/04/17.
  */
class Bech32Spec extends FunSuite {
  test("valid checksums") {
    val inputs = Seq(
      "A12UEL5L",
      "a12uel5l",
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
      "?1ezyfcl"
    )
    val outputs = inputs.map(Bech32.decode)
    assert(outputs.length == inputs.length)
  }

  test("invalid checksums") {
    val inputs = Seq(
      " 1nwldj5",
      "\u007f1axkwrx",
      "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
      "pzry9x0s0muk",
      "1pzry9x0s0muk",
      "x1b4n0q5v",
      "li1dgmt3",
      "de1lg7wt\u00ff"
    )

    inputs.map(address => {
      intercept[Exception] {
        Bech32.decodeWitnessAddress(address)
      }
    })
  }

  test("decode addresses") {
    val inputs = Seq(
      "QC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KQ52AT0" -> "0014751e76e8199196d454941c45d1b3a323f1433bd6",
      "tq1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qucc3th" -> "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      "tq1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesswsl2d" -> "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
      "qc1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses8mexl8" -> "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
    )
    inputs.map {
      case (address, bin) =>
        val (_, _, bin1) = Bech32.decodeWitnessAddress(address)
        assert(bin1.toHex == bin.substring(4))
    }
  }

  test("create addresses") {
    assert(Bech32.encodeWitnessAddress("qc", 0, hex"751e76e8199196d454941c45d1b3a323f1433bd6") == "QC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KQ52AT0".toLowerCase)
    assert(Bech32.encodeWitnessAddress("tq", 0, hex"1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262") == "tq1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qucc3th")
    assert(Bech32.encodeWitnessAddress("tq", 0, hex"000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433") == "tq1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesswsl2d")
  }

  test("reject invalid addresses") {
    val addresses = Seq(
      "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
      "qc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
      "QC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
      "qc1rw5uspcuh",
      "qc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
      "qca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035",
      "QC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
      "tq1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
      "Qc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
      "tq1pw508d6qejxtdg4y5r3zarqfsj6c3",
      "tq1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
      "qc1gmk9yu"
    )
    addresses.map(address => {
      intercept[Exception] {
        Bech32.decodeWitnessAddress(address)
      }
    })
  }
}
