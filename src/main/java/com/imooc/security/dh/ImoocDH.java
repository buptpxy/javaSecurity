package main.java.com.imooc.security.dh;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public class ImoocDH {

	private static String src = "imooc security dh";
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkDH();
	}
	public static void jdkDH() {
		
		try {
			//初始化发送方密钥
			KeyPairGenerator senderkKeyPairGenerator = KeyPairGenerator.getInstance("DH");//密钥对生成器实例化
			senderkKeyPairGenerator.initialize(512);
			KeyPair senderKeyPair = senderkKeyPairGenerator.generateKeyPair();//用密钥对生成器生成密钥对
			byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();//获得密钥对中的公钥并编码，用于发送给接收方
			
			//初始化接收方密钥
			/*密钥工厂用于将密钥（Key 类型的不透明加密密钥）转换成密钥规范（底层密钥材料的透明表示），反之亦然。
			密钥工厂是双向的。也就是说，它们允许根据给定的密钥规范（密钥材料）构建不透明的密钥对象，也允许获取以恰当格式表示的密钥对象的底层密钥材料。
			对于同一个密钥可以存在多个兼容的密钥规范。例如，可以使用 DSAPublicKeySpec 或 X509EncodedKeySpec 指定 DSA 公钥。密钥工厂可用于兼容密钥规范之间的转换。*/
			KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);//这个类将文件中的字节数组读出转换为密钥对象。
			PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);//密钥工厂把密钥对象转换成x509规范的公钥
			DHParameterSpec dhParameterSpec = ((DHPublicKey)receiverPublicKey).getParams();// 剖析获取到的公钥，得到其参数
			
			KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");// 实例化密钥对生成器
			receiverKeyPairGenerator.initialize(dhParameterSpec);//用得到的公钥的参数初始化密钥生成器
			KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();//生成密钥对
			byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();//计算得接收方编码后的公钥
			PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();//计算得接收方私钥
			
			//密钥构建
			KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
			receiverKeyAgreement.init(receiverPrivateKey);
			receiverKeyAgreement.doPhase(receiverPublicKey, true);
			SecretKey receiverDesKey = receiverKeyAgreement.generateSecret("DES");//生成用des加密的本地密钥
			
			KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
			x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);
			PublicKey senderPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec);
			KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
			PrivateKey senderPrivateKey = senderKeyPair.getPrivate();
			senderKeyAgreement.init(senderPrivateKey);
			senderKeyAgreement.doPhase(senderPublicKey, true);
			SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
			
			if(Objects.equals(receiverDesKey, receiverDesKey)){
				System.out.println("双方密钥相同");
			}
			
			//加密
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdkDH encrypt:" + Base64.encodeBase64String(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
			result = cipher.doFinal(result);
			System.out.println("jdkDH decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
