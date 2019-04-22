package com.pxy.security.dh;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class ImoocDH {

	private static String src = "imooc security dh";
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkDH();
	}
	public static void jdkDH() {
		
		try {
			//��ʼ�����ͷ���Կ
			KeyPairGenerator senderkKeyPairGenerator = KeyPairGenerator.getInstance("DH");//��Կ��������ʵ����
			senderkKeyPairGenerator.initialize(512);
			KeyPair senderKeyPair = senderkKeyPairGenerator.generateKeyPair();//����Կ��������������Կ��
			byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();//�����Կ���еĹ�Կ�����룬���ڷ��͸����շ�
			
			//��ʼ�����շ���Կ
			/*��Կ�������ڽ���Կ��Key ���͵Ĳ�͸��������Կ��ת������Կ�淶���ײ���Կ���ϵ�͸����ʾ������֮��Ȼ��
			��Կ������˫��ġ�Ҳ����˵������������ݸ�������Կ�淶����Կ���ϣ�������͸������Կ����Ҳ�����ȡ��ǡ����ʽ��ʾ����Կ����ĵײ���Կ���ϡ�
			����ͬһ����Կ���Դ��ڶ�����ݵ���Կ�淶�����磬����ʹ�� DSAPublicKeySpec �� X509EncodedKeySpec ָ�� DSA ��Կ����Կ���������ڼ�����Կ�淶֮���ת����*/
			KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);//����ཫ�ļ��е��ֽ��������ת��Ϊ��Կ����
			PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);//��Կ��������Կ����ת����x509�淶�Ĺ�Կ
			DHParameterSpec dhParameterSpec = ((DHPublicKey)receiverPublicKey).getParams();// ������ȡ���Ĺ�Կ���õ������
			
			KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");// ʵ������Կ��������
			receiverKeyPairGenerator.initialize(dhParameterSpec);//�õõ��Ĺ�Կ�Ĳ�����ʼ����Կ������
			KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();//������Կ��
			byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();//����ý��շ������Ĺ�Կ
			PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();//����ý��շ�˽Կ
			
			//��Կ����
			KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
			receiverKeyAgreement.init(receiverPrivateKey);
			receiverKeyAgreement.doPhase(receiverPublicKey, true);
			SecretKey receiverDesKey = receiverKeyAgreement.generateSecret("DES");//������des���ܵı�����Կ
			
			KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
			x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);
			PublicKey senderPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec);
			KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
			PrivateKey senderPrivateKey = senderKeyPair.getPrivate();
			senderKeyAgreement.init(senderPrivateKey);
			senderKeyAgreement.doPhase(senderPublicKey, true);
			SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
			
			if(Objects.equals(receiverDesKey, receiverDesKey)){
				System.out.println("˫����Կ��ͬ");
			}
			
			//����
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdkDH encrypt:" + Base64.encodeBase64String(result));
			
			//����
			cipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
			result = cipher.doFinal(result);
			System.out.println("jdkDH decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
