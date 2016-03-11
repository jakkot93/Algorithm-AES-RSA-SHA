package com.jakkot93.aes;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainActivity extends Activity {

    static final String TAG = "JK";

    double start, koniec;

    SecretKey sk128 = null;
    SecretKey sk192 = null;
    SecretKey sk256 = null;

    Key publicK1024 = null;
    Key privateK1024 = null;

    Key publicK2048 = null;
    Key privateK2048 = null;

    Key publicK4096 = null;
    Key privateK4096 = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String seed = "Ciąg pseudolosowy";
        String TestText = "Bezpieczeństwo komunikacji w aplikacjach";

        byte[] aaa = new byte[16];
        new Random().nextBytes(aaa);

        try {

            KeyGenerator kg = KeyGenerator.getInstance("AES");  //inicjalizacja algorytmu AES w generatorze kluczy
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); //ustawienie generatora ciągu pseudolosowego
            sr.setSeed(seed.getBytes());    //ustawienie ziarna
            kg.init(128, sr);   // długość klucza wynosi 256
            sk128 = kg.generateKey();    //wyrobienie klucza

            KeyGenerator kg2 = KeyGenerator.getInstance("AES");
            SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG");
            sr2.setSeed(seed.getBytes());
            kg2.init(256, sr2);
            sk256 = kg2.generateKey();

            KeyGenerator kg3 = KeyGenerator.getInstance("AES");
            SecureRandom sr3 = SecureRandom.getInstance("SHA1PRNG");
            sr3.setSeed(seed.getBytes());
            kg3.init(192, sr3);
            sk192 = kg3.generateKey();

            KeyPairGenerator kpg1 = KeyPairGenerator.getInstance("RSA");
            kpg1.initialize(1024);
            KeyPair kp1 = kpg1.genKeyPair();
            publicK1024 = kp1.getPublic();
            privateK1024 = kp1.getPrivate();
            Log.i(TAG, "PublicKey1024: " + publicK1024.getEncoded().length);
            Log.i(TAG, "PrivateKey1024: " + privateK1024.getEncoded().length);

            KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("RSA");
            kpg2.initialize(2048);
            KeyPair kp2 = kpg2.genKeyPair();
            publicK2048 = kp2.getPublic();
            privateK2048 = kp2.getPrivate();
            Log.i(TAG, "PublicKey2048: " + publicK2048.getEncoded().length);
            Log.i(TAG, "PrivateKey2048: " + privateK2048.getEncoded().length);

            start = System.nanoTime();
            KeyPairGenerator kpg3 = KeyPairGenerator.getInstance("RSA");
            kpg3.initialize(4096);
            KeyPair kp3 = kpg3.genKeyPair();
            publicK4096 = kp3.getPublic();
            privateK4096 = kp3.getPrivate();
            koniec = System.nanoTime() - start;
            Log.v(TAG, "Czas " + koniec / 1000000);

            Log.i(TAG, "PublicKey4096: " + publicK4096.getEncoded().length);
            Log.i(TAG, "PrivateKey4096: " + privateK4096.getEncoded().length);

            String a = DigestFromMsg(TestText.getBytes());
            Log.i(TAG, "Oryginalna wiadomość: " + TestText);
            Log.i(TAG, "Skrót wiadomości: " + a);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void aesKey(View view) {

        byte[] encodedBytes = null;
        byte[] decodedBytes = null;

        byte[] msg = new byte[102400];
        new Random().nextBytes(msg);

        try {
            Cipher c = Cipher.getInstance("AES");

            //szyfrowanie Key128
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.ENCRYPT_MODE, sk128);
                encodedBytes = c.doFinal(msg);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas szyfrowania Key128: " + koniec / 1000000);

            //odszyfrowanie Key128
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.DECRYPT_MODE, sk128);
                decodedBytes = c.doFinal(encodedBytes);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas odszyfrowania Key128: " + koniec / 1000000);

            //szyfrowanie Key192
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.ENCRYPT_MODE, sk192);
                encodedBytes = c.doFinal(msg);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas szyfrowania Key192: " + koniec / 1000000);

            //odszyfrowanie Key192
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.DECRYPT_MODE, sk192);
                decodedBytes = c.doFinal(encodedBytes);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas odszyfrowania Key192: " + koniec / 1000000);

            //szyfrowanie Key256
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.ENCRYPT_MODE, sk256);
                encodedBytes = c.doFinal(msg);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas szyfrowania Key256: " + koniec / 1000000);

            //odszyfrowanie Key256
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.DECRYPT_MODE, sk256);
                decodedBytes = c.doFinal(encodedBytes);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas odszyfrowania Key256: " + koniec / 1000000);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void aesMsg(View view) {
        byte[] encodedBytes = null;
        byte[] decodedBytes = null;

        byte[] msg;
        int l = 0;
        try {
            Cipher c = Cipher.getInstance("AES");

            for (int j = 0; j < 100; j++) {
                l += 1024;
                msg = new byte[l];
                new Random().nextBytes(msg);

                //szyfrowanie Msg
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    c.init(Cipher.ENCRYPT_MODE, sk256);
                    encodedBytes = c.doFinal(msg);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas szyfrowania " + j + " KeyMsg: " + koniec / 1000000);

                //odszyfrowanie KeyMsg
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    c.init(Cipher.DECRYPT_MODE, sk256);
                    decodedBytes = c.doFinal(encodedBytes);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas odszyfrowania " + j + " KeyMsg: " + koniec / 1000000);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void aesBlock(View view) {

        byte[] encodedBytes = null;
        byte[] decodedBytes = null;

        byte[] msg;
        int l = 0;
        try {
            Cipher c = Cipher.getInstance("AES");

            for (int j = 0; j < 5; j++) {
                l += 16;
                msg = new byte[l];
                new Random().nextBytes(msg);

                //szyfrowanie Msg
                koniec = 0.0;
                start = System.nanoTime();
                for (int i = 0; i < 100000; i++) {
                    c.init(Cipher.ENCRYPT_MODE, sk256);
                    encodedBytes = c.doFinal(msg);
                }
                koniec = (System.nanoTime() - start) / 100000;
                Log.i(TAG, "Czas szyfrowania + " + j + " : " + koniec / 1000000);
                Log.i(TAG, "Długość + " + j + " : " + encodedBytes.length);

                //odszyfrowanie KeyMsg
                koniec = 0.0;
                start = System.nanoTime();
                for (int i = 0; i < 100000; i++) {
                    c.init(Cipher.DECRYPT_MODE, sk256);
                    decodedBytes = c.doFinal(encodedBytes);
                }
                koniec = (System.nanoTime() - start) / 100000;
                Log.i(TAG, "Czas odszyfrowania + " + j + " : " + koniec / 1000000);
            }

            l = -1;
            for (int j = 0; j < 5; j++) {
                l += 16;
                msg = new byte[l];
                new Random().nextBytes(msg);

                //szyfrowanie Msg
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 100000; i++) {
                    c.init(Cipher.ENCRYPT_MODE, sk256);
                    encodedBytes = c.doFinal(msg);
                }
                koniec = (System.nanoTime() - start) / 100000;
                Log.i(TAG, "Czas szyfrowania - " + j + " : " + koniec / 1000000);
                Log.i(TAG, "Długość - " + j + " : " + encodedBytes.length);

                //odszyfrowanie KeyMsg
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 100000; i++) {
                    c.init(Cipher.DECRYPT_MODE, sk256);
                    decodedBytes = c.doFinal(encodedBytes);
                }
                koniec = (System.nanoTime() - start) / 100000;
                Log.i(TAG, "Czas odszyfrowania - " + j + " : " + koniec / 1000000);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void rsaKey(View view) {

        byte[] encodedBytes = null;
        byte[] decodedBytes = null;

        byte[] msg = new byte[128];
        new Random().nextBytes(msg);

        try {
            Cipher c = Cipher.getInstance("RSA");

            //szyfrowanie Key1024
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.ENCRYPT_MODE, publicK1024);
                encodedBytes = c.doFinal(msg);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas szyfrowania Key1024: " + koniec / 1000000);
            Log.i(TAG, "Długość wiadomości Key1024: " + encodedBytes.length);

            //odszyfrowanie Key1024
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.DECRYPT_MODE, privateK1024);
                decodedBytes = c.doFinal(encodedBytes);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas odszyfrowania Key1024: " + koniec / 1000000);

            //szyfrowanie Key2048
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.ENCRYPT_MODE, publicK2048);
                encodedBytes = c.doFinal(msg);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas szyfrowania Key2048: " + koniec / 1000000);
            Log.i(TAG, "Długość wiadomości Key2048: " + encodedBytes.length);

            //odszyfrowanie Key2048
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.DECRYPT_MODE, privateK2048);
                decodedBytes = c.doFinal(encodedBytes);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas odszyfrowania Key2048: " + koniec / 1000000);

            //szyfrowanie Key4096
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.ENCRYPT_MODE, publicK4096);
                encodedBytes = c.doFinal(msg);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas szyfrowania Key4096: " + koniec / 1000000);
            Log.i(TAG, "Długość wiadomości Key4096: " + encodedBytes.length);

            //odszyfrowanie Key4096
            koniec = 0;
            start = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                c.init(Cipher.DECRYPT_MODE, privateK4096);
                decodedBytes = c.doFinal(encodedBytes);
            }
            koniec = (System.nanoTime() - start) / 1000;
            Log.i(TAG, "Czas odszyfrowania Key4096: " + koniec / 1000000);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void rsaMsg(View view) {

        byte[] encodedBytes = null;
        byte[] decodedBytes = null;

        byte[] msg;
        int l = 0;
        try {
            Cipher c = Cipher.getInstance("RSA");

            for (int j = 0; j < 10; j++) {
                l += 16;
                msg = new byte[l];
                new Random().nextBytes(msg);

                //szyfrowanie Msg
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    c.init(Cipher.ENCRYPT_MODE, publicK1024);
                    encodedBytes = c.doFinal(msg);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas szyfrowania RSA " + j + " : " + koniec / 1000000);
                Log.i(TAG, "Długość " + l + " = " + encodedBytes.length);

                //odszyfrowanie KeyMsg
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    c.init(Cipher.DECRYPT_MODE, privateK1024);
                    decodedBytes = c.doFinal(encodedBytes);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas odszyfrowania RSA" + j + " : " + koniec / 1000000);
                //Log.i(TAG, "Długość " + l + " = " + decodedBytes.length);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void aesRsa(View view) {

        byte[] encodedBytesRsa = null;
        byte[] decodedBytesRsa = null;
        byte[] encodedBytesAes = null;
        byte[] decodedBytesAes = null;

        byte[] msg;
        int l = 0;
        try {
            Cipher cRSA = Cipher.getInstance("RSA");
            Cipher cAES = Cipher.getInstance("AES");

            for (int j = 0; j < 8; j++) {
                l += 8;
                msg = new byte[l];
                new Random().nextBytes(msg);

                //szyfrowanie Msg RSA
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    cRSA.init(Cipher.ENCRYPT_MODE, publicK1024);
                    encodedBytesRsa = cRSA.doFinal(msg);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas szyfrowania RSA " + j + " : " + koniec / 1000000);

                //szyfrowanie Msg AES
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    cAES.init(Cipher.ENCRYPT_MODE, sk128);
                    encodedBytesAes = cAES.doFinal(msg);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas szyfrowania AES " + j + " : " + koniec / 1000000);

                //odszyfrowanie Msg RSA
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    cRSA.init(Cipher.DECRYPT_MODE, privateK1024);
                    decodedBytesRsa = cRSA.doFinal(encodedBytesRsa);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas odszyfrowania RSA " + j + " : " + koniec / 1000000);

                //odszyfrowanie Msg AES
                koniec = 0;
                start = System.nanoTime();
                for (int i = 0; i < 1000; i++) {
                    cAES.init(Cipher.DECRYPT_MODE, sk128);
                    decodedBytesAes = cAES.doFinal(encodedBytesAes);
                }
                koniec = (System.nanoTime() - start) / 1000;
                Log.i(TAG, "Czas odszyfrowania AES " + j + " : " + koniec / 1000000);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String DigestFromMsg(byte[] msg) {
        MessageDigest digest;
        byte[] hash = null;

        try {
            digest = MessageDigest.getInstance("SHA-256");
            digest.update(msg);
            hash = digest.digest();
            String a = hash.toString().trim();
            Log.i(TAG, "Skrót " + a);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            Log.e(TAG, "DIGEST error");
            e.printStackTrace();
        }
        StringBuilder buf = new StringBuilder();
        for (byte b : hash) {
            int halfbyte = (b >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                buf.append((0 <= halfbyte) && (halfbyte <= 9) ? (char) ('0' + halfbyte) : (char) ('a' + (halfbyte - 10)));
                halfbyte = b & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }
}