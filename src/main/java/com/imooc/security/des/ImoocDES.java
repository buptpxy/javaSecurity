package main.java.com.imooc.security.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;
import java.security.Security;

public class ImoocDES {

	private static String src = "imooc security des"; 
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkDES();
		bcDES();
	}

	public static void jdkDES() {
		try {
			//随机生成密钥
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			keyGenerator.init(56);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] key = secretKey.getEncoded();
			//转换成可用秘密密钥
			DESKeySpec desKeySpec = new DESKeySpec(key);//转换成des密钥格式
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			Key convertSecretKey = factory.generateSecret(desKeySpec);//利用secretKeyFactory给密钥加密
			//加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");//算法/模式/填充方式
			cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk des encrypt:" + Hex.encodeHexString(result));
			//解密
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk des decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public static void bcDES() {
		try {
			//随机生成密钥
			Security.addProvider(new BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");
			keyGenerator.init(56);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] key = secretKey.getEncoded();
			//转换成可用秘密密钥
			DESKeySpec desKeySpec = new DESKeySpec(key);//转换成des密钥格式
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			Key convertSecretKey = factory.generateSecret(desKeySpec);//利用secretKeyFactory给密钥加密
			//加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");//算法/模式/填充方式
			cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc des encrypt:" + Hex.encodeHexString(result));
			//解密
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc des decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
