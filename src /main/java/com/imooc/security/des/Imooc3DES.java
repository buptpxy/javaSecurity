package main.java.com.imooc.security.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

public class Imooc3DES {
	private static String src = "imooc security 3des";
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdk3DES();
		bc3DES();
	}
	
	public static void jdk3DES() {
		try {
			//生成密钥
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			keyGenerator.init(new SecureRandom());//自动给密钥一个默认长度
			SecretKey secretKey = keyGenerator.generateKey();//生成密钥
			byte[] key = secretKey.getEncoded();//将密钥编码
			
			//转换为可用密钥
			DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(key);//将密钥转换为可用的格式
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertKey = factory.generateSecret(deSedeKeySpec);//将密钥加密
			
			//利用密钥对内容加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk3DES encrypt:" + Hex.encodeHexString(result));
			
			//利用同一密钥对内容解密
			cipher.init(Cipher.DECRYPT_MODE, convertKey);
			result = cipher.doFinal(result);
			System.out.println("jdk3DES decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void bc3DES() {
		try {
			//生成密钥
			Security.addProvider(new BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");
			keyGenerator.init(new SecureRandom());//自动给密钥一个默认长度
			SecretKey secretKey = keyGenerator.generateKey();//生成密钥
			byte[] key = secretKey.getEncoded();//将密钥编码
			
			//转换为可用密钥
			DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(key);//将密钥转换为可用的格式
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertKey = factory.generateSecret(deSedeKeySpec);//将密钥加密
			
			//利用密钥对内容加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc3DES encrypt:" + Hex.encodeHexString(result));
			
			//利用同一密钥对内容解密
			cipher.init(Cipher.DECRYPT_MODE, convertKey);
			result = cipher.doFinal(result);
			System.out.println("bc3DES decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
