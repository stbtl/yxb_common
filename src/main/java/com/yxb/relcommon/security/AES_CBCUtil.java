package com.yxb.relcommon.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 对称加密
 */
public final class AES_CBCUtil {

    private static final int KEY_LENGTH = 128;
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * 加密
     * @param encData 需要加密的数据
     * @param key key值
     * @param salt 盐值
     * @return 加密后的数据
     */
    public static String encode(String encData, String key, String salt)  {
        try{
            SecretKey secretKey = generatePBEKey(key, salt, KEY_LENGTH);

            byte[] iv = salt.getBytes();

            byte[] bytePlainText = Utf8.encode(encData);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

            byte[] byteEncrypted = cipher.doFinal(bytePlainText);

            return new String(Hex.encode(byteEncrypted));
        }catch(Exception e){
            throw new SecurityException("加密失败！", e);
        }
    }

    /**
     * 解密
     * @param decData 需要解密的数据
     * @param key key值
     * @param salt 盐值
     * @return 解密后的数据
     */
    public static String decode(String decData, String key, String salt)  {
        try{
            SecretKey secretKey = generatePBEKey(key, salt, KEY_LENGTH);

            byte[] iv = salt.getBytes();

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            byte[] plainByte = cipher.doFinal(Hex.decode(decData));

            return Utf8.decode(plainByte);
        }catch(Exception e){
            throw new SecurityException("解密失敗！", e);
        }
    }

    private static SecretKey generatePBEKey(String key, String salt, int keyLength) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(key.toCharArray(), Hex.decode(salt), 1024, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        SecretKey secretKey = new SecretKeySpec( factory.generateSecret(keySpec).getEncoded(), "AES");
        return secretKey;
    }
}
