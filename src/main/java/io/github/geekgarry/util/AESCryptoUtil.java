package io.github.geekgarry.util;

import io.github.geekgarry.exceptions.JWTCreationException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * author     : geekplus
 * email      :
 * date       : 10/16/24 3:12 AM
 * description: //TODO
 */
public class AESCryptoUtil {

    private static final String SPECIAL_CHARS = "!@#$%^&*()_-+=[{]};:>|./?";
    private static final String LETTERS_AND_DIGITS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Random RANDOM = new Random();

    public static String AESKey16() {
        return generateRandomString(16);
    }

    public static String AESKey24() {
        return generateRandomString(24);
    }

    public static String AESKey32() {
        return generateRandomString(32);
    }

    public static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            // 随机选择字母还是特殊字符
            if (RANDOM.nextBoolean()) {
                // 随机选择一个字母
                sb.append(LETTERS_AND_DIGITS.charAt(RANDOM.nextInt(LETTERS_AND_DIGITS.length())));
            } else {
                // 随机选择一个特殊字符
                sb.append(SPECIAL_CHARS.charAt(RANDOM.nextInt(SPECIAL_CHARS.length())));
            }
        }
        return sb.toString();
    }

    /**
     * 随机生成秘钥
     */
    public static String getAESKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            //要生成多少位，只需要修改这里即可128, 192或256
            SecretKey sk = kg.generateKey();
            byte[] b = sk.getEncoded();
            String s = byteToHexString(b);
            return s;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new JWTCreationException("没有此算法~~~", e);
        }
    }
    /**
     * 使用指定的字符串生成秘钥
     */
    public static String getAESKeyByPass(String keyWord) {
        //生成秘钥
        String password;
        if(keyWord != null && !keyWord.trim().isEmpty()){
            password = keyWord;
        }else{
            password = "plusplus";
        }

        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            // kg.init(128);//要生成多少位，只需要修改这里即可128, 192或256
            //SecureRandom是生成安全随机数序列，password.getBytes()是种子，只要种子相同，序列就一样，所以生成的秘钥就一样。
            kg.init(128, new SecureRandom(password.getBytes()));
            SecretKey sk = kg.generateKey();
            byte[] b = sk.getEncoded();
            String s = byteToHexString(b);
            return s;
        }catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new JWTCreationException("没有此算法~~~", e);
        }
    }

    /**
     * byte数组转化为16进制字符串
     * @param bytes
     * @return
     */
    public static String byteToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String strHex=Integer.toHexString(bytes[i]);
            if(strHex.length() > 3) {
                sb.append(strHex.substring(6));
            } else {
                if(strHex.length() < 2) {
                    sb.append("0" + strHex);
                } else {
                    sb.append(strHex);
                }
            }
        }
        return sb.toString();
    }

    public static String generateHexKey(String keyWord, int length) {
        //生成秘钥
        String password;
        if(keyWord != null && !keyWord.trim().isEmpty()){
            password = keyWord;
        }else{
            password = "plusplus";
        }

        SecureRandom random = new SecureRandom(password.getBytes());
        BigInteger randomNumber = new BigInteger(length * 4, random);
        String hexKey = randomNumber.toString(16);
        while (hexKey.length() < length) {
            hexKey = "0" + hexKey;
        }
        return hexKey.toUpperCase();
    }

//    private static byte[] generateAESKey(int keySize) {
//        SecureRandom random = new SecureRandom();
//        byte[] key = new byte[keySize];
//        random.nextBytes(key);
//        return key;
//    }

    public static byte[] generateAESKey16() throws NoSuchAlgorithmException {
        return generateAESKey(128);
    }

    public static byte[] generateAESKey32() throws NoSuchAlgorithmException {
        return generateAESKey(256);
    }

    private static byte[] generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }
}
