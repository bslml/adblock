
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.lang.reflect.Array;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.lang.reflect.Array;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SecurityUtils {

    private  static String priKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICWwIBAAKBgHB/XUS4TtNBIw8HoELFejLK1PVQtC9sz8xxGzWymFVkIlT1tvCz\n" +
            "fKfg5HhPZ918gWyeDGDUKlUQzV1DNSeI9Ea+Az+z+P69VBuG81i7ucphNv8SyJY2\n" +
            "crOnSenAC+prpqBs3bMijT2xjuzPxyqfyPUcb9XtPF5f+MaENfcfDJabAgMBAAEC\n" +
            "gYAt4wW8PiGI8gzG2Kl6EurhRPLQjXax0YSBM7GRmaOhURLf7MoOLGgwYf9PQ7Ru\n" +
            "F5cDIwSRinkp8YyS+hL4aViZ44DFAc/tVU01xUZ5XGDhCMtNNZYSnl04ku/ZKHhz\n" +
            "eT5hg3RKRjaMNLtII8tbBLxTWxqclPFkJkYDLNcykyVtwQJBANrF4llcE5tyiU1N\n" +
            "nno0ov1TUN16h+8Hk+DZm65OTzhridg/K/RCbbQP5ehEuSNIvLaYoCAwzFeonIui\n" +
            "jMacFikCQQCDo/GS884VoxpNmj+v73Cdk0G3eeBE5EvwzR6ueVhgwlIhCEZXxRnQ\n" +
            "JYkT1afXhcYZBJsf/1ce7m5bxBuuNPcjAkEAi1TaSsUsq6Tvsy8LDpO1dpd4egYO\n" +
            "yvpNgTe2QfYX2DwNJ49cJA2mprY1W49hRgqOPdDIspfBnNaDFR9qfxdruQJAJ6y5\n" +
            "mjiw3ASUYN8kYrofjt5a6BlrZlgIK0MnBB6+bCsk5Z/A06Mr7HfjoH68X1CKK/Af\n" +
            "cL1cXI4v5KhuT0rXUQJALYoW9/4z7TYVcqMIDKOEWQJsZjwUvJ1PHTvAlByxhy0I\n" +
            "O+/MtFisCmHRnajAt8IFASL2pM4XbFkQzGAZ23DYqQ==\n" +
            "-----END RSA PRIVATE KEY-----";
    private static String pubKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHB/XUS4TtNBIw8HoELFejLK1PVQ\n" +
            "tC9sz8xxGzWymFVkIlT1tvCzfKfg5HhPZ918gWyeDGDUKlUQzV1DNSeI9Ea+Az+z\n" +
            "+P69VBuG81i7ucphNv8SyJY2crOnSenAC+prpqBs3bMijT2xjuzPxyqfyPUcb9Xt\n" +
            "PF5f+MaENfcfDJabAgMBAAE=\n" +
            "-----END PUBLIC KEY-----";

    private static final String TAG = SecurityUtils.class.getSimpleName();
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static SecurityUtils securityUtils;
    private SecurityUtils(){}
    public static final SecurityUtils getInstance()  {
        if(securityUtils==null){
            synchronized (SecurityUtils.class){
                    securityUtils = new SecurityUtils();
                    try {
                        publicKey = RSAUtils.loadPublicKey(new ByteArrayInputStream(pubKey.getBytes()));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    try {
                        privateKey = RSAUtils.loadPrivateKey(new ByteArrayInputStream(priKey.getBytes()));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
            }
        }
        return securityUtils;
    }

    /** 
     * 解密 
     * @param cipherText 密文 
     * @return 返回解密后的字符�? 
     * @throws Exception
     */  
    private String decryptKey(String cipherText) throws Exception {
        byte[] decryptByte = RSAUtils.decryptData(Base64Utils.decode(cipherText), privateKey);  
        String decryptStr = new String(decryptByte, "utf-8");
        return decryptStr;
    }


    /** 
     * 加密 
     * @param plainTest 明文 
     * @return  返回加密后的密文 
     * @throws Exception
     */
    public String encryptKey(String plainTest) throws Exception {
        byte[] encryptByte = RSAUtils.encryptData(plainTest.getBytes(), publicKey);  
        String afterencrypt = Base64Utils.encode(encryptByte);
        return afterencrypt;
    }

    public String decryptText(String cipherText, String cipherAesKey)
    {
        try {
            String plainKey = decryptKey(cipherAesKey);
            String plainText = AESUtil.decrypt(cipherText,plainKey);
            return plainText;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}  

/**
 * Created by T800 on 2017/12/6.
 */

