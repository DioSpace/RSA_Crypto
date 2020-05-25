package com.my;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSAChinese {
    /**
     * 创建密钥对生成器，指定加密和解密算法为RSA
     *
     * @param keylen
     * @return
     */
    public String[] createKey(int keylen) {// 输入密钥长度
        String[] output = new String[5]; // 用来存储密钥的e n d p q
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keylen); // 指定密钥的长度，初始化密钥对生成器
            KeyPair kp = kpg.generateKeyPair(); // 生成密钥对
            RSAPublicKey puk = (RSAPublicKey) kp.getPublic();
            RSAPrivateCrtKey prk = (RSAPrivateCrtKey) kp.getPrivate();
            BigInteger e = puk.getPublicExponent();
            BigInteger n = puk.getModulus();
            BigInteger d = prk.getPrivateExponent();
            BigInteger p = prk.getPrimeP();
            BigInteger q = prk.getPrimeQ();
            output[0] = e.toString();
            output[1] = n.toString();
            output[2] = d.toString();
            output[3] = p.toString();
            output[4] = q.toString();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAChinese.class.getName()).log(Level.SEVERE, null, ex);
        }
        return output;
    }


    /**
     * 加密在RSA公钥中包含有两个整数信息：e和n。对于明文数字m,计算密文的公式是m的e次方再与n求模。
     *
     * @param clearText 明文
     * @param eStr      公钥
     * @param nStr
     * @return
     */
    public String encrypt(String clearText, String eStr, String nStr) {
        String secretText = new String();

        try {
            clearText = URLEncoder.encode(clearText, "GBK");
            byte text[] = clearText.getBytes("GBK");//将字符串转换成byte类型数组，实质是各个字符的二进制形式
            BigInteger mm = new BigInteger(text);//二进制串转换为一个大整数
            clearText = mm.toString();

            BigInteger e = new BigInteger(eStr);
            BigInteger n = new BigInteger(nStr);
            byte[] ptext = clearText.getBytes("UTF8"); // 获取明文的大整数
            BigInteger m = new BigInteger(ptext);
            BigInteger c = m.modPow(e, n);
            secretText = c.toString();
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(RSAChinese.class.getName()).log(Level.SEVERE, null, ex);
        }
        return secretText;
    }


    /**
     * 解密
     *
     * @param secretText 密文
     * @param dStr       私钥
     * @param nStr
     * @return
     */
    public String decrypt(String secretText, String dStr, String nStr) {
        StringBuffer clearTextBuffer = new StringBuffer();
        BigInteger d = new BigInteger(dStr);// 获取私钥的参数d,n
        BigInteger n = new BigInteger(nStr);
        BigInteger c = new BigInteger(secretText);
        BigInteger m = c.modPow(d, n);// 解密明文
        byte[] mt = m.toByteArray();// 计算明文对应的字符串并输出
        for (int i = 0; i < mt.length; i++) {
            clearTextBuffer.append((char) mt[i]);
        }
        String temp = clearTextBuffer.toString();//temp为明文的字符串形式
        BigInteger b = new BigInteger(temp);//b为明文的BigInteger类型
        byte[] mt1 = b.toByteArray();

        try {
            String clearText = (new String(mt1, "GBK"));
            clearText = URLDecoder.decode(clearText, "GBK");
            return clearText;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        RSAChinese rsa = new RSAChinese();
        String[] str = rsa.createKey(1024);
        for (String key: str) {
            System.out.println("key : \n" + key);
        }
        System.out.println(str.length);
        String clearText = "123abc测试";
        String secretText = rsa.encrypt(clearText, str[0], str[1]);
        System.out.println("明文是：" + clearText);
        System.out.println("密文是：" + secretText);
        System.out.println("解密后的明文是：" + rsa.decrypt(secretText, str[2], str[1]));
    }
} 