package com.naphaso.jsodium;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import com.rfksystems.blake2b.Blake2b;
import java.util.Base64;
import org.junit.Test;

/**
 * @author
 */
public class CustomSodiumTest {

  private static LazySodiumJava ls = new LazySodiumJava(new SodiumJava());

  @Test
  public void testcrypto_box_seal() {

    byte[] pub = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
    byte[] sec = new byte[Sodium.crypto_box_SECRETKEYBYTES];

    int i = Sodium.crypto_box_keypair(sec, pub);

    String mess = "123456";

    byte[] ciper = new byte[mess.length() + 48];

    int i1 = Sodium.crypto_box_seal(ciper, mess.getBytes(), pub);
    System.out.println("Sodium.crypto_box_seal " + Base64.getEncoder().encodeToString(ciper));

    byte[] cip = new byte[mess.length() + 48];
    ls.cryptoBoxSeal(cip, mess.getBytes(), mess.getBytes().length, pub);
    System.out.println("ls.cryptoBoxSeal " + Base64.getEncoder().encodeToString(ciper));

  }


  @Test
  public void testgenricHash() {

//    byte[] pub = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
//    byte[] sec = new byte[Sodium.crypto_box_SECRETKEYBYTES];
//
//    int i = Sodium.crypto_box_keypair(sec, pub);
//
//
//    byte[] random = new byte[8];
//
//    Sodium.randombytes_buf(random);
////
////
////
//    System.out.println(Base64.getEncoder().encodeToString(sec));
//    System.out.println(Base64.getEncoder().encodeToString(pub));
//    System.out.println(Base64.getEncoder().encodeToString(random));

    byte[] sec = Base64.getDecoder().decode("1ouCGgA7GlgtEuEZ3PAzk7XWSZGhRPtYhE2U5zj9dQg=");
    byte[] pub = Base64.getDecoder().decode("cQMdvPT6i5Ks3hJADV+A8ARvD9/rz6rN1vr4dtvU6Xg=");
    byte[] random = Base64.getDecoder().decode("N+nMNOvw/l4=");

    KeyPair AsymmetricKey = new KeyPair(Key.fromBytes(pub), Key.fromBytes(sec));

    lazyGenericHash(pub, AsymmetricKey, random);

    sodiuii(pub, AsymmetricKey, random);


  }

  private void sodiuii(byte[] pub, KeyPair asymmetricKey, byte[] random) {
//    KeyPair keyPair = new KeyPair(Key.fromBytes(random),
//        Key.fromBytes(asymmetricKey.getSecretKey().getAsBytes()));
//
//    byte[] shardKey = new byte[32];
//
//    Sodium.crypto_box_seal(shardKey, keyPair.getSecretKey().getAsBytes(),
//        keyPair.getPublicKey().getAsBytes());

//    System.out.println(Base64.getEncoder().encodeToString(shardKey));

    Blake2b di = new Blake2b();
    di.update(asymmetricKey.getSecretKey().getAsBytes(), 0,
        asymmetricKey.getSecretKey().getAsBytes().length);
    di.update(pub, 0, pub.length);
    di.update(random, 0, random.length);

//    byte[] result = new byte[Sodium.crypto_hash_sha256_statebytes()];
//    Sodium.crypto_generichash_init(result, null, 0, 64);
//
//    Sodium.crypto_generichash_update(result, shardKey, shardKey.length);
//
//    Sodium.crypto_generichash_update(result, pub,
//        pub.length);
//
//    Sodium.crypto_generichash_update(result, random, random.length);

    byte[] bytes = new byte[64];
//    int aFinal = Sodium.crypto_generichash_final(result, bytes, 64);

    int digest = di.digest(bytes, 0);

    System.out.println(digest);

    System.out.println("Blake2b. " + Base64.getEncoder().encodeToString(bytes));
  }

  private void lazyGenericHash(byte[] pub, KeyPair asymmetricKey, byte[] random) {
//    KeyPair keyPair = new KeyPair(Key.fromBytes(random),
//        Key.fromBytes(asymmetricKey.getSecretKey().getAsBytes()));
//
//    Key shardKey = ls.cryptoScalarMult(keyPair.getSecretKey(), keyPair.getPublicKey());
//
//    System.out.println(Base64.getEncoder().encodeToString(shardKey.getAsBytes()));

    byte[] result = new byte[ls.cryptoGenericHashStateBytes()];
    ls.getSodium().crypto_generichash_init(result, null, 0, 64);

    ls.getSodium()
        .crypto_generichash_update(result, asymmetricKey.getSecretKey().getAsBytes(),
            asymmetricKey.getSecretKey().getAsBytes().length);

    ls.getSodium().crypto_generichash_update(result, pub,
        pub.length);

    ls.getSodium().crypto_generichash_update(result, random, random.length);

    byte[] bytes = new byte[64];
    int aFinal = ls.getSodium().crypto_generichash_final(result, bytes, 64);

    System.out.println(aFinal);

    System.out.println("ls. " + Base64.getEncoder().encodeToString(bytes));
  }

  @Test
  public void testKeypair() {

    byte[] pub = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
    byte[] sec = new byte[Sodium.crypto_box_SECRETKEYBYTES];

    int i = Sodium.crypto_box_keypair(sec, pub);
    System.out.println(i);
    System.out.println(Base64.getEncoder().encodeToString(sec));
    System.out.println(Base64.getEncoder().encodeToString(pub));

  }

  @Test
  public void testRandombuf() {

    // 测试 randombuf
    byte[] bytes = ls.randomBytesBuf(8);
    byte[] xx = new byte[8];
    Sodium.randombytes_buf(xx);
    System.out.println(Base64.getEncoder().encodeToString(bytes));
    System.out.println(Base64.getEncoder().encodeToString(xx));
  }

  @Test
  public void testcrypto_scalarmult() {

    byte[] pub = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
    byte[] sec = new byte[Sodium.crypto_box_SECRETKEYBYTES];

    int i = Sodium.crypto_box_keypair(sec, pub);
    System.out.println(i);
    System.out.println(Base64.getEncoder().encodeToString(sec));
    System.out.println(Base64.getEncoder().encodeToString(pub));

    byte[] shardKey = new byte[32];

//    Sodium.randombytes_buf(shardKey);

    Sodium.crypto_scalarmult(shardKey, sec, pub);

    System.out.println("Sodium.crypto_scalarmult " + Base64.getEncoder().encodeToString(shardKey));

    Key key = ls.cryptoScalarMult(Key.fromBytes(sec), Key.fromBytes(pub));
    System.out
        .println("ls.cryptoScalarMult " + Base64.getEncoder().encodeToString(key.getAsBytes()));

  }

  @Test
  public void test201305() {

    // 没来一个就比较一下

    String messsage = "1234567";

    // 201305
    byte[] ad = "eb3e3b21c2dd4ee7a4fb641a666736acDAAAAAAAAAA=".getBytes();
    byte[] pub = ls.sodiumHex2Bin(
        "445c6242 11f8b9bf 7e800421 8c74ea1a b54019c8 3ea8f966 0bd221d2 7a831290".replace(" ", ""));
    byte[] key = ls.sodiumHex2Bin("7eb9a972 a28525bb 609bbd7a".replace(" ", ""));

    String s = encode201305(messsage, key, pub, ad);
    System.out.println(s);
    byte[] m = messsage.getBytes();
    int i = Sodium
        .crypto_aead_chacha20poly1305_decrypt(m, Base64.getDecoder().decode(s), ad, key, pub);
    System.out.println(new String(m));

    byte[] ciper = new byte[messsage.length() + 16];

    Sodium.crypto_aead_chacha20poly1305_encrypt(ciper, messsage.getBytes(), ad, key, pub);

    System.out.println("Sodium.crypto_aead_chacha2 "+ Base64.getEncoder().encodeToString(ciper));

    String s1 = decode201305(ciper, key, pub, ad);
    System.out.println("decode201305( " + s1);

  }


  // 解密201305
  public static String decode201305(byte[] message, byte[] publicKey, byte[] SymmetricKey,
      byte[] ad) {

    byte[] ci2 = new byte[message.length];

    int adLength = ad.length;

    if (null == ad) {
      adLength = 0;
    }

    // 下面是解密
    if (ls.cryptoAeadChaCha20Poly1305Decrypt(ci2, new long[]{message.length}, null, message,
        message.length, ad, adLength, publicKey, SymmetricKey)) {

      return new String(ci2);
    } else {
      // todo print 解密失败
      return null;
    }

  }

  // 加密201305
  public static String encode201305(String source, byte[] publicKey, byte[] SymmetricKey,
      byte[] ad) {

    // 这个16 是 crypto_aead_chacha20poly1305_ABYTES 16U
    byte[] ciperText = new byte[source.getBytes().length + 16];
    if (ls.cryptoAeadChaCha20Poly1305Encrypt(ciperText, new long[]{ciperText.length},
        source.getBytes(),
        source.getBytes().length, ad, ad.length, null, publicKey, SymmetricKey)) {
      return Base64.getEncoder().encodeToString(ciperText);
    } else {
      // todo print 加密失败
      return null;
    }

  }

}
