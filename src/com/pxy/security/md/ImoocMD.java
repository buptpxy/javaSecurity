package com.pxy.security.md;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ImoocMD {

	private static String src = "imooc security md";
	public static void main(String[] args) {
		// bc�ṩ��MD4����,ccֻ�Ƕ�jdk��md2��md5�������˼�
		jdkMD2();
		jdkMD5();
		bcMD4();
		bcMD5();
		ccMD2();
		ccMD5();
	}

	public static void jdkMD2() {
		try {
			MessageDigest md = MessageDigest.getInstance("MD2");
			byte[] md2 = md.digest(src.getBytes());
			System.out.println("jdkMD2:" + Hex.encodeHexString(md2));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void jdkMD5() {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5 = md.digest(src.getBytes());
			System.out.println("jdkMD5:" + Hex.encodeHexString(md5));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	//ʹ��bcʵ�ֵķ���һ��������ӽ�jdk��provider�У�����jdk�ķ�ʽʹ��
	public static void bcMD4() {
		try {
			Security.addProvider(new BouncyCastleProvider());
			MessageDigest md = MessageDigest.getInstance("MD4");
			byte[] md4 = md.digest(src.getBytes());
			System.out.println("bcMD4:" + Hex.encodeHexString(md4));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	//ʹ��bcʵ�ֵķ�����
	public static void bcMD5() {
		Digest digest = new MD5Digest();
		digest.update(src.getBytes(), 0, src.getBytes().length);//�����byte[],��ʼλ��,��������ĳ���
		byte[] md5 = new byte[digest.getDigestSize()];//����һ������Ϊ���ɵ�ժҪ���ȵ�byte����
		digest.doFinal(md5, 0);//�����byte���飬��ʼλ��
		System.out.println("bcMD5:" + org.bouncycastle.util.encoders.Hex.toHexString(md5));
	}
	
	public static void ccMD2() {
		System.out.println("ccMD2:" + DigestUtils.md2Hex(src));
	}
	
	public static void ccMD5() {
		System.out.println("ccMD5:" + DigestUtils.md5Hex(src));
	}
}
