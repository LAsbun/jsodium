package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 23/07/16.
 */
public class SignTest extends TestCase {

  public static final int MESSAGE_SIZE = 4000;

  @Test
  public void test_crypto_sign() {

    System.out.println(Sodium.int_test());
    System.out.println(0);

    byte[] message = new byte[MESSAGE_SIZE];
    byte[] message2 = new byte[MESSAGE_SIZE];
    byte[] publicKey = new byte[Sodium.crypto_sign_PUBLICKEYBYTES];
    byte[] secretKey = new byte[Sodium.crypto_sign_SECRETKEYBYTES];
    byte[] signedMessage = new byte[Sodium.crypto_sign_BYTES + MESSAGE_SIZE];

    Sodium.randombytes_buf(message);

    assertTrue(Sodium.crypto_sign_keypair(publicKey, secretKey) == 0);
    assertTrue(Sodium.crypto_sign(signedMessage, message, secretKey) >= 0);
    assertTrue(Sodium.crypto_sign_open(message2, signedMessage, publicKey) >= 0);
    assertEquals(Utils.encode(message), Utils.encode(message2));

    signedMessage[0] = (byte) (signedMessage[0] ^ 1);

    assertFalse(Sodium.crypto_sign_open(message2, signedMessage, publicKey) >= 0);
  }

  @Test
  public void test_crypto_sign_detached() {
    byte[] message = new byte[MESSAGE_SIZE];
    byte[] signature = new byte[Sodium.crypto_sign_BYTES];
    byte[] publicKey = new byte[Sodium.crypto_sign_PUBLICKEYBYTES];
    byte[] secretKey = new byte[Sodium.crypto_sign_SECRETKEYBYTES];

    Sodium.randombytes_buf(message);

    assertTrue(Sodium.crypto_sign_keypair(publicKey, secretKey) == 0);
    assertTrue(Sodium.crypto_sign_detached(signature, message, secretKey) >= 0);
    assertTrue(Sodium.crypto_sign_verify_detached(signature, message, publicKey) >= 0);

    signature[0] = (byte) (signature[0] ^ 1);

    assertFalse(Sodium.crypto_sign_verify_detached(signature, message, publicKey) >= 0);
  }

  @Test
  public void test_tt() {

    byte[] out = new byte[44];
    byte[] key = hexToBytes("5B389DE3EE9C4F10EC8A49F6E6DF3012D8BE0AFE3FC9C85D059F1B63F1AFE49A");

    byte[] salt = hexToBytes("1FC1C8530CE58EF9C15B6355064018BBE320B9A791D63A5F7E22A9F5515D7ED5");

    int i = Sodium
        .crypto_generichash_blake2b_salt_personal(out, out.length, null, 0, key, key.length,
            salt, null, 0);

    System.out.println(i);
    System.out.println(bytesToHex(out));


  }

  private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

  private static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  // The following is from https://stackoverflow.com/a/140861/3526705
  private static byte[] hexToBytes(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
          + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
  }
}
