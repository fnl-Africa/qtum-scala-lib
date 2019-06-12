package org.qtumproject.qtum.reference

import java.io.InputStreamReader

import org.qtumproject.qtum.Crypto.PrivateKey
import org.qtumproject.qtum.{Base58, Base58Check, Bech32, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA, Script}
import org.json4s.DefaultFormats
import org.json4s.JsonAST.{JBool, JString, JValue}
import org.json4s.jackson.JsonMethods
import org.scalatest.FunSuite
import scodec.bits.ByteVector

import scala.util.Try

class KeyEncodingSpec extends FunSuite {
  implicit val format = DefaultFormats

  test("valid keys") {
    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/key_io_valid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].map(KeyEncodingSpec.check)
  }

  test("invalid keys") {
    val stream = classOf[KeyEncodingSpec].getResourceAsStream("/data/key_io_invalid.json")
    val json = JsonMethods.parse(new InputStreamReader(stream))

    json.extract[List[List[JValue]]].foreach {
      _ match {
        case JString(value) :: Nil =>
          assert(!KeyEncodingSpec.isValidBase58(value))
          assert(!KeyEncodingSpec.isValidBech32(value))
        case unexpected => throw new IllegalArgumentException(s"don't know how to parse $unexpected")
      }
    }
  }
}

object KeyEncodingSpec {
  def isValidBase58(input: String): Boolean = Try {
    val (prefix, bin) = Base58Check.decode(input)
    prefix match {
      case Base58.Prefix.SecretKey | Base58.Prefix.SecretKeyTestnet => Try(PrivateKey(bin)).isSuccess
      case Base58.Prefix.PubkeyAddress | Base58.Prefix.PubkeyAddressTestnet => bin.length == 20
      case _ => false
    }
  } getOrElse (false)

  def isValidBech32(input: String): Boolean = Try {
    Bech32.decodeWitnessAddress(input) match {
      case (hrp, 0, bin) if (hrp == "qc" || hrp == "tq" || hrp == "qcrt") && (bin.length == 20 || bin.length == 32) => true
      case _ => false
    }
  } getOrElse (false)

  def check(data: List[JValue]): Unit = {
    data match {
      case JString(encoded) :: JString(hex) :: obj :: Nil => {
        val bin = ByteVector.fromValidHex(hex)
        val JBool(isPrivkey) = obj \ "isPrivkey"
        val isCompressed = obj \ "isCompressed" match {
          case JBool(value) => value
          case _ => None
        }
        val JString(chain) = obj \ "chain"
        if (isPrivkey) {
          val (version, data) = Base58Check.decode(encoded)
          assert(version == Base58.Prefix.SecretKey || version == Base58.Prefix.SecretKeyTestnet)
          assert(data.take(32) == bin)
        } else encoded.substring(0, 2) match {
          case "qc" | "tq" | "QC" | "TQ" =>
            val (_, tag, program) = Bech32.decodeWitnessAddress(encoded)
            val op :: OP_PUSHDATA(hash, _) :: Nil = Script.parse(bin)
            assert(Script.simpleValue(op) == tag)
            assert(program == hash)

          case _ => encoded.head match {
            case 'Q' | 'q'  =>
              val (version, data) = Base58Check.decode(encoded)
              assert(version == Base58.Prefix.PubkeyAddress || version == Base58.Prefix.PubkeyAddressTestnet)
              val OP_DUP :: OP_HASH160 :: OP_PUSHDATA(hash, _) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil = Script.parse(bin)
              assert(data == hash)
            case 'M' | 'm' =>
              val (version, data) = Base58Check.decode(encoded)
              assert(version == Base58.Prefix.ScriptAddress || version == Base58.Prefix.ScriptAddressTestnet)
              val OP_HASH160 :: OP_PUSHDATA(hash, _) :: OP_EQUAL :: Nil = Script.parse(bin)
              assert(data == hash)
          }
        }
      }
      case unexpected => throw new IllegalArgumentException(s"don't know how to parse $unexpected")
    }
  }
}
