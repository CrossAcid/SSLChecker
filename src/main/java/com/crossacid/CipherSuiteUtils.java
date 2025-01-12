package com.crossacid;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

public class CipherSuiteUtils {

    /**
     * @description 获取java虚拟机支持的密码套件
     * @param protocol SSLv3,TLSv1,TLSv1.1 ... 中的一个
     * @param rand 随机数
     * @return 支持的密码套件列表
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws KeyManagementException KeyManagementException
     */
    public static String[] getJVMSupportedCipherSuites(String protocol, SecureRandom rand) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance(protocol);
        sc.init(null, null, rand);
        return sc.getSocketFactory().getSupportedCipherSuites();
    }

    /**
     *
     * @param protocol SSLv3,TLSv1,TLSv1.1 ... 中的一个
     * @param sslEnabledProtocols 启动的protocol
     * @param sslCipherSuites 启动的密码套件
     * @param rand 随机数
     * @param trustManagers 信任管理器
     * @param keyManagers 密钥管理器
     * @return 自定义getSSLSocketFactory
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws KeyManagementException KeyManagementException
     */
    public static SSLSocketFactory getSSLSocketFactory(String protocol, String[] sslEnabledProtocols, String[] sslCipherSuites, SecureRandom rand, TrustManager[] trustManagers, KeyManager[] keyManagers) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, trustManagers, rand);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        if (null != sslEnabledProtocols || null != sslCipherSuites)
            sslSocketFactory = new SSLUtils.CustomSSLSocketFactory(sslSocketFactory, sslEnabledProtocols, sslCipherSuites);
        return sslSocketFactory;
    }

    /**
     *
     * @param protocol 使用的SSL协议
     * @param cipherSuite 密码套件
     * @return 密码套件分数
     */
    public static int getCipherSuitScore(String protocol, String cipherSuite) {
        int score = 100; // 初始化满分

        // 检查是否为匿名套件 或 导出 套件
        if (cipherSuite.contains("ANON") || cipherSuite.contains("EXPORT")) {
            score = 0;
        }

        // 检查是否使用 RC4
        if (cipherSuite.contains("RC4")) {
            score = 0;
        }

        // 检查是否使用 3DES/DES/RC2/IDEA
        if (cipherSuite.contains("3DES") || cipherSuite.contains("DES") || cipherSuite.contains("RC2") || cipherSuite.contains("IDEA")) {
            score = Math.min(score, 80);
        }

        // 检查是否不使用 AEAD 算法
        if (!cipherSuite.contains("GCM") && !cipherSuite.contains("CHACHA20") && !cipherSuite.contains("POLY1305")) {
            score = Math.min(score, 80);
        }

        // 检查是否不使用 DHE/ECDHE, TLSv1.3不需要ECDHE来证明
        if (!cipherSuite.contains("DHE") && !cipherSuite.contains("ECDHE") && !Objects.equals(protocol, "TLSv1.3")) {
            score = Math.min(score, 80);
        }

        // 获取密钥长度评分
        int keyStrengthScore = getKeyStrengthScore(cipherSuite, protocol);
        score = (int) (score * (keyStrengthScore / 100.0)); // 按比例调整总分

        return score;
    }

    /**
     *
     * @param cipherSuite 密码套件
     * @param protocol 使用的ssl协议
     * @return 密钥长度分数
     */
    private static int getKeyStrengthScore(String cipherSuite, String protocol) {
        if (Objects.equals(protocol, "TLSv1.3")) {
            return 100;
        }
        if (cipherSuite.contains("GCM") || cipherSuite.contains("_POLY1305_")) {
            return 100;
        }
        if (cipherSuite.contains("3DES")) {
            return 80;
        }
        if (cipherSuite.contains("_256_")) {
            return 100;
        } else if (cipherSuite.contains("_128_") || cipherSuite.contains("_168_")) {
            return 80;
        } else if (cipherSuite.contains("_40_") || cipherSuite.contains("_56_")) {
            return 20;
        } else if (cipherSuite.contains("_NULL_")) {
            return 0;
        }
        return 0; // 默认无效
    }
}
