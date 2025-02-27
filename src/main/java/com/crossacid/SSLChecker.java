package com.crossacid;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;


public class SSLChecker {

    // 检查结果
    CheckResult checkResult = new CheckResult();

    protected static String TAB = "  ";
    // 支持的协议
    protected StringBuilder supportSSLProtocolsDesc = new StringBuilder();

    // 需要测试的协议列表
    protected List<String> protocolsToTest = Arrays.asList("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3");

    // 加密套件列表
    protected HashSet<String> cipherSuites = new HashSet<>();

    // 支持的加密套件列表
    protected StringBuilder supportCipherSuites = new StringBuilder();

    // 自定义的信任管理器
    protected TrustManager[] trustManagers;
    protected KeyManager[] keyManagers;

    // 超时时间设置
    protected int connectTimeout = 0; // default = infinite
    protected int readTimeout = 1000;

    // 分数计算
    protected int cipherSuitScoreMin = 100;
    protected int cipherSuitScoreMax = 0;
    protected int cipherSuitScore;
    protected int protocolScore = 0;
    protected int score = 0;


    protected StringBuilder result = new StringBuilder();
    protected StringBuilder others = new StringBuilder();
    protected StringBuilder suggestions = new StringBuilder();

    protected String critical = "";

    public SSLChecker() {}

    public String check(String domain, int port, boolean giveSuggestions) {

        // 1.1 获取证书信息
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        // 是否支持SNI

        try {
            SSLSocket socket = (SSLSocket) factory.createSocket(domain, port);

            // 尝试SNI连接
            try {
                SSLParameters sslParameters = socket.getSSLParameters();
                sslParameters.setServerNames(Collections.singletonList(new SNIHostName(domain)));
                socket.setSSLParameters(sslParameters);

                socket.startHandshake();
                SSLSession sslSession = socket.getSession();

                checkResult.setCertificateChainList(sslSession.getPeerCertificates());
                checkResult.setSupportSNIDesc(true);
            } catch (SSLHandshakeException e) {
                checkResult.setSupportSNIDesc(false);
                socket = (SSLSocket) factory.createSocket(domain, port);
                // 发起不带 SNI 的握手
                socket.startHandshake();
                SSLSession sslSession = socket.getSession();

                checkResult.setCertificateChainList(sslSession.getPeerCertificates());
            } finally {
                socket.close();
            }
        } catch (IOException e) {
            System.out.println(domain + " Default check failed, retrying with custom trust manager");
            checkResult.setCertificateChainList(SSLUtils.getCertificatesWithoutValidation(domain, port));
        }
        Certificate[] certificates = checkResult.getCertificateChainList();
        if (certificates.length == 0) {
            System.err.println("No certificate found");
            return null;
        }
        if (!(certificates[0] instanceof X509Certificate)) {
            return "Not a X509 Certificate";
        }
        if (certificates.length == 1) {
            if (((X509Certificate) certificates[0]).getIssuerX500Principal().equals(((X509Certificate) certificates[0]).getSubjectX500Principal())) {
                critical = "T";
                others.append(TAB).append("该域名使用自签名证书");
                suggestions.append(TAB).append(" - ").append("该域名使用自签名证书").append("\n");
            }
            checkResult.setCertificateType("Self-signed certificate");
        }

        this.trustManagers = SSLUtils.getTrustManagers(false);
        this.keyManagers = SSLUtils.getKeyManagers();

        // 1.2 证书基本信息
        checkResult.setCertificateCommonName(CertificateUtils.getCommonName(certificates[0], "Subject"));
        checkResult.setCertificateIssuerName(CertificateUtils.getCommonName(certificates[0], "Issuer"));
        checkResult.setCertificateEncryptionAlgorithm(CertificateUtils.getEncryptionAlgorithm(certificates[0]));
        checkResult.setCertificateBrand(CertificateUtils.getBrand(certificates[0]));
        checkResult.setCertificateSigAlgName(((X509Certificate) certificates[0]).getSigAlgName());
        checkResult.setCertificateType(!(checkResult.getCertificateType() == null) ? checkResult.getCertificateType(): CertificateUtils.getType(certificates[0]));
        checkResult.setCertificateStartTime(Utils.formatDate(((X509Certificate)certificates[0]).getNotBefore()));
        checkResult.setCertificateEndTime(Utils.formatDate(((X509Certificate)certificates[0]).getNotAfter()));
        checkResult.setCertificateOrganization(CertificateUtils.getOrganization(certificates[0]));
        checkResult.setCertificateOU(CertificateUtils.getOrganizationalUnit(certificates[0]));
        try {
            if (certificates.length > 1) {
                String revokeResult = CertificateUtils.getRevokedStatus((X509Certificate) certificates[0], (X509Certificate) certificates[1]);
                checkResult.setCertificateRevokedStatus(revokeResult);
            } else {
                checkResult.setCertificateRevokedStatus("Self-signed certificate");
            }
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
        if (checkResult.getCertificateSigAlgName().contains("SHA1")) {
            critical = "T";
        }
        try {
            checkResult.setCertificateSAN(CertificateUtils.getSubjectAlternativeName(certificates[0]));
        } catch (CertificateParsingException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }

        // 2. 检查证书链信息
        checkCertChainInfo(certificates);
        checkResult.getCertificateChainInfo();
        if (!checkResult.getExpiredInfo().isEmpty()) {
            others.append(checkResult.getExpiredInfo()).append("\n");
            suggestions.append(TAB).append(" - ").append("请保证证书在有效期内").append("\n");
            critical = "T";
        }

        // 3. 检测支持的SSL协议
        for (String protocol : protocolsToTest) {
            checkProtocolSupport(domain, port, protocol);
        }

        if (checkResult.getSupportSSLProtocols().isEmpty()) {
            result.append("No SSL protocol supported\n");
            return result.toString();
        }

        if (checkResult.getSupportSSLProtocols().contains("SSLv3")) {
            suggestions.append(TAB).append(" - ").append("启用SSLv3导致评分最高为B").append("\n");
            if (critical.compareTo("B") < 0 || critical.isEmpty()) {
                critical = "B";
            }
        }

        if (checkResult.getSupportSSLProtocols().contains("TLSv1")) {
            suggestions.append(TAB).append(" - ").append("启用TLSv1导致评分最高为B").append("\n");
            if (critical.compareTo("B") < 0 || critical.isEmpty()) {
                critical = "B";
            }
        }

        if (checkResult.getSupportSSLProtocols().contains("TLSv1.1")) {
            suggestions.append(TAB).append(" - ").append("启用TLSv1.1导致评分最高为B").append("\n");
            if (critical.compareTo("B") < 0 || critical.isEmpty()) {
                critical = "B";
            }
        }

        // 4. 支持的加密套件
        for (String protocol : checkResult.getSupportSSLProtocols()) {
            System.out.println("Checking "+ domain + " with " + protocol);
            if ("SSLv3".equals(protocol) || "TLSv1".equals(protocol)) {
                suggestions.append(TAB).append(" - ").append("启用").append(protocol).append("将导致PCI DSS不合规").append("\n");
            }
            checkProtocolSupportCipherSuites(domain, port, protocol);
        }


        // 5. 总结
        // 5.1 ATS检测
        checkResult.setConformToATS(checkATS());

        // 5.2 PCI DSS检测
        checkResult.setConformToPCIDSS(checkPCIDSS());

        // 6. 生成结果
        return generateResult(domain, this.result, giveSuggestions);
    }


    /**
     *
     * @return 是否符合 PCI DSS
     * @description 检测 PCI DSS 规则是否符合 （DH parameters 2048+ bits java api不包含该检测）
     */
    private boolean checkPCIDSS() {

        // SSL 2.0, SSL 3.0 and TLS 1.0 不支持
        for (String protocol : checkResult.getSupportSSLProtocols()) {
            if (protocol.equals("SSLv2Hello") || protocol.equals("SSLv3") || protocol.equals("TLSv1")) {
                return false;
            }
        }
        if (encryptionAlgorithmATSAndPCIDSSStandard()) return false;
        // 包含弱密钥和导出套件，或密钥长度不够，均不符合PCI DSS标准
        return !checkResult.isWeakCipherSuit() && supportCipherSuites.indexOf("INSECURE") == -1 && !Objects.equals(critical, "T");

        // 不安全的重协商和压缩在TLS 1.2或TLS 1.3中被禁用，故第一步和这一步等价，不再重述
    }

    /**
     *
     * @return 是否符合 ATS
     * @description 检测 ATS 规则是否符合
     */
    private boolean checkATS() {
        // 支持TLS 1.2或更高版本
        if (!checkResult.getSupportSSLProtocols().contains("TLSv1.2") && !checkResult.getSupportSSLProtocols().contains("TLSv1.3")) {
            return false;
        }
        // 必须支持以下加密套件之一或更多，即AES-128或AES-256
        List<String> AESSearchList = List.of("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                                                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                                                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                                                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                                                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                                                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        boolean containsAnyAES128OrAES256 = Utils.containsAny(supportCipherSuites, AESSearchList);
        if (!containsAnyAES128OrAES256) {
            return false;
        }
        // 正向加密
        List<String> FSSearchList = List.of("ECDHE", "DHE");
        boolean containsAnyForwardSecrecy = Utils.containsAny(supportCipherSuites, FSSearchList);
        if (!containsAnyForwardSecrecy) {
            return false;
        }
        // 服务器端证书签名密钥至少为2048位的RSA密钥或至少256位的ECC密钥
        if (encryptionAlgorithmATSAndPCIDSSStandard()) {
            return false;
        }
        // 服务器证书的哈希算法必须为SHA-2，其摘要长度至少为256位（即SHA-256及以上）
        List<String> SigAlgNameSearchList = List.of("SHA256", "SHA384", "SHA512", "SHA512/224", "SHA512/256",
                                                    "SHA3256", "SHA3384", "SHA3512");
        return !Objects.equals(critical, "T") && Utils.containsAny(new StringBuilder(checkResult.getCertificateSigAlgName()), SigAlgNameSearchList);
    }

    /**
     *
     * @return 是否符合ATS和PCI DSS的加加密算法标准
     * @description 必须为RSA > 2048 bits或者ECC > 256 bits
     */
    private boolean encryptionAlgorithmATSAndPCIDSSStandard() {
        String[] parts = checkResult.getCertificateEncryptionAlgorithm().split(" ");
        if (parts.length == 3) {
            if (parts[0].equals("RSA")) {
                int keySize = Integer.parseInt(parts[1]);
                return keySize < 2048;
            } else if (parts[0].equals("EC")) {
                int keySize = Integer.parseInt(parts[1]);
                return keySize < 256;
            } else {
                return false;
            }
        }
        return false;
    }

    /**
     * @description 生成最后的分数
     */
    private void generateScore() {
        // 1.协议分数
        Map<String, Integer> protocolScores = new HashMap<>();
        protocolScores.put("SSLv3", 50);
        protocolScores.put("TLSv1", 70);
        protocolScores.put("TLSv1.1", 80);
        protocolScores.put("TLSv1.2", 90);
        protocolScores.put("TLSv1.3", 100);

        int min = 100;
        int max = 0;
        for (String protocol : checkResult.getSupportSSLProtocols()) {
            if (protocolScores.containsKey(protocol)) {
                min = min < protocolScores.get(protocol) ? min : protocolScores.get(protocol);
                max = max > protocolScores.get(protocol) ? max : protocolScores.get(protocol);
            }
        }
        this.protocolScore += (max + min) / 2;

        // 2.密码套件分数
        this.cipherSuitScore = (this.cipherSuitScoreMax + this.cipherSuitScoreMin) / 2;

                // 3.总分
        this.score = (int) (0.5 * this.protocolScore + 0.5 * this.cipherSuitScore);
    }

    /**
     *
     * @param domain 待检测域名
     * @param protocol 待检测协议
     * @description 检测该域名对应协议下支持的加密套件并保存
     */
    private void  checkProtocolSupportCipherSuites(String domain, int port, String protocol) {
        String[] supportedCipherSuites = new String[0];
        SecureRandom rand = new SecureRandom();
        try {
            supportedCipherSuites = CipherSuiteUtils.getJVMSupportedCipherSuites(protocol, rand);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(protocol + " Not supported by client");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        cipherSuites.clear();
        cipherSuites.addAll(Arrays.asList(supportedCipherSuites));
        if (cipherSuites.isEmpty()) {
            System.err.println("No overlapping cipher suites found for protocol " + protocol);
            protocolsToTest.remove(protocol);
            return;
        }
        supportCipherSuites.append(TAB).append(TAB).append(protocol).append(": ").append("\n");
        for (String cipherSuite : cipherSuites) {
            SSLSocketFactory sslSocketFactory;
            try {
                trustManagers = SSLUtils.getTrustManagers(true);
                sslSocketFactory = CipherSuiteUtils.getSSLSocketFactory(protocol, new String[]{protocol}, new String[]{cipherSuite}, rand, trustManagers, keyManagers);
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                System.out.println(e.getMessage());
                throw new RuntimeException(e);
            }
            InetSocketAddress address = new InetSocketAddress(domain, port);
            try (SSLSocket socket = SSLUtils.createSSLSocket(address, domain, port, connectTimeout, readTimeout, sslSocketFactory)) {
                socket.startHandshake();
                SSLSession sess = socket.getSession();
                assert protocol.equals(sess.getProtocol());
                assert cipherSuite.equals(sess.getCipherSuite());
                int currentScore = CipherSuiteUtils.getCipherSuitScore(protocol, cipherSuite);
                if (currentScore == 0) {
                    checkResult.setWeakCipherSuit(true);
                }
                this.cipherSuitScoreMax = Math.max(this.cipherSuitScoreMax, currentScore);
                this.cipherSuitScoreMin = Math.min(this.cipherSuitScoreMin, currentScore);

                String cipherSuitJudge = currentScore == 100 ? "" : (currentScore >= 64 ? "WEAK" : "INSECURE");
                if (cipherSuite.contains("RC4")) {
                    suggestions.append(TAB).append(" - ").append("启用").append(cipherSuite).append("导致评分最高为B(不推荐使用RC4)").append("\n");
                    if (critical.compareTo("B") < 0 || critical.isEmpty()) {
                        critical = "B";
                    }
                }
                supportCipherSuites.append(TAB).append(TAB).append(TAB).append(TAB).append(cipherSuite).append(" ").append(cipherSuitJudge).append("\n");
            } catch (IOException ignored) {

            }

            if (protocolsToTest.isEmpty()) {
                System.err.println("This client supports none of the requested protocols: "
                        + List.of(protocolsToTest));
                System.err.println("Exiting.");
                System.exit(1);
            }
        }
    }

    /**
     *
     * @param certificates 证书
     * @description 检测证书链信息
     */
    public void checkCertChainInfo(Certificate[] certificates) {
        boolean flag = false;
        for (TrustManager tm : this.trustManagers) {
            if (tm instanceof X509TrustManager x509TrustManager) {
                X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();
                for (X509Certificate rootCert : acceptedIssuers) {
                    // 检查根证书是否匹配最后一个中间证书的颁发者并输出根证书
                    if (rootCert.getSubjectX500Principal().equals(((X509Certificate)certificates[certificates.length - 1]).getIssuerX500Principal())) {
                        Certificate[] newCertificates = Arrays.copyOf(certificates, certificates.length + 1);
                        newCertificates[newCertificates.length - 1] = rootCert;
                        checkResult.setCertificateChainList(newCertificates);
                        flag = true;
                    }
                }
            }
        }
        // 在系统的受信证书中无该根证书
        if (!flag) {
            critical = "T";
            others.append(TAB).append("该证书链可能不完整或根证书非可信根证书");
            suggestions.append(TAB).append(" - ").append("该证书链可能不完整或根证书非可信根证书").append("\n");
        }

    }

    /**
     *
     * @param domain 待检测域名
     * @param protocol 待检测协议
     * @description 检测对应域名是否支持该协议
     */
    public void checkProtocolSupport(String domain, int port, String protocol) {
        try {
            SSLContext sslContext = SSLContext.getInstance(protocol);
            sslContext.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            }, new SecureRandom());
            // 获取 SSLSocketFactory
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(domain, port);
            socket.setEnabledProtocols(new String[]{protocol});

            // 启用所有加密套件
            socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

            // 启动握手
            socket.startHandshake();
            checkResult.getSupportSSLProtocols().add(protocol);
            this.supportSSLProtocolsDesc.append(TAB).append(TAB).append(protocol).append(" support").append("\n");

            socket.close();
        } catch (UnknownHostException e) {
            System.err.println("Unknown host: " + domain);
        } catch (IOException | NoSuchAlgorithmException e) {
            this.supportSSLProtocolsDesc.append(TAB).append(TAB).append(protocol).append(" not support").append("\n");
        } catch (KeyManagementException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     *
     * @param domain 待检测域名
     * @param result 检测结果字符串
     * @param giveSuggestions 是否给出建议
     * @return 最终的result
     * @description 生成result字符串
     */
    public String generateResult(String domain, StringBuilder result, boolean giveSuggestions) {

        result.append("检测域名: ").append(domain).append("\n");

        // 1.证书信息
        result.append("证书信息").append("\n");
        result.append("通用名称: ").append(checkResult.getCertificateCommonName()).append("\n");
        result.append("颁发者: ").append(checkResult.getCertificateIssuerName()).append("\n");
        result.append("启用SNI: ").append(checkResult.isSupportSNIDesc()).append("\n");
        result.append("弱密钥检测: ").append(checkResult.isWeakCipherSuit()).append("\n");
        result.append("加密算法: ").append(checkResult.getCertificateEncryptionAlgorithm()).append("\n");
        result.append("签名算法: ").append(checkResult.getCertificateSigAlgName()).append("\n");
        result.append("证书品牌: ").append(checkResult.getCertificateBrand()).append("\n");
        result.append("证书类型: ").append(checkResult.getCertificateType()).append("\n");
        result.append("开始时间: ").append(checkResult.getCertificateStartTime()).append("\n");
        result.append("结束时间: ").append(checkResult.getCertificateEndTime()).append("\n");
        result.append("吊销状态: ").append(checkResult.getCertificateRevokedStatus()).append("\n");
        result.append("组织机构: ").append(checkResult.getCertificateOrganization()).append("\n");
        result.append("部门: ").append(checkResult.getCertificateOrganization()).append("\n");
        result.append("备用名称: ").append(checkResult.getCertificateSAN()).append("\n");
        result.append("\n");

        // 2.证书链信息
        result.append("证书链信息: ").append("\n");
        result.append(checkResult.getCertificateChainInfo()).append("\n");

        // 3.协议与套件
        result.append("协议与套件:").append("\n");
        // 3.1 支持协议
        result.append(TAB).append("支持协议:").append("\n");
        result.append(supportSSLProtocolsDesc).append("\n");
        // 3.2 支持套件
        result.append(TAB).append("支持的加密套件:").append("\n");
        result.append(supportCipherSuites).append("\n");
        result.append("\n");

        // 4.总结
        result.append("总结:").append("\n");
        result.append(TAB).append("是否符合ATS:").append(checkResult.isConformToATS()).append("\n");
        result.append(TAB).append("是否符合PCI DSS:").append(checkResult.isConformToPCIDSS()).append("\n");

        generateScore();
        result.append(TAB).append("评级: ").append(score).append(" ");
        if (critical.equals("T")) {
            result.append("T").append("\n");
        } else {
            if (score >= 80) {
                if (critical.equals("B")) {
                    result.append("B").append("\n");
                } else {
                    result.append("A").append("\n");
                }
            } else if (score >= 65) {
                result.append("B").append("\n");
            } else if (score >= 50) {
                result.append("C").append("\n");
            } else if (score >= 35) {
                result.append("D").append("\n");
            } else {
                result.append("E").append("\n");
            }
        }
        result.append("\n");

        result.append(others);
        result.append("\n");

        // 5.建议
        if (giveSuggestions) {
            result.append("建议:").append("\n").append(suggestions);
        }

        return result.toString();
    }
}
