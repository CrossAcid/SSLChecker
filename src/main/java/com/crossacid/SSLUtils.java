package com.crossacid;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class SSLUtils {

    /**
     *
     * @param address (域名，443)
     * @param readTimeout 超时
     * @param connectTimeout 连接超时
     * @param sslSocketFactory SSLSocketFactory
     * @return 创建SSLSocket
     * @throws IOException IOException
     */
    public static SSLSocket getCustomSSLSocket(InetSocketAddress address, int readTimeout, int connectTimeout, SSLSocketFactory sslSocketFactory) throws IOException {
        Socket sock = new Socket();
        sock.setSoTimeout(readTimeout);
        sock.connect(address, connectTimeout);
        return (SSLSocket) sslSocketFactory.createSocket(sock, address.getHostName(), address.getPort(), true);
    }

    public static Certificate[] getCertificatesWithoutValidation(String domain, int port) {
        X509Certificate[] serverCertificates;
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(getKeyManagers(), getCustomTrustManagers(), new java.security.SecureRandom());
            // 获取 SSLSocketFactory
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(domain, port);

            // 启用所有加密套件
            socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

            // 启动握手
            socket.startHandshake();

            // 获取 SSL 会话
            SSLSession session = socket.getSession();
            serverCertificates = (X509Certificate[]) session.getPeerCertificates();

            socket.close();
        } catch (NoSuchAlgorithmException | IOException | KeyManagementException e) {
            throw new RuntimeException(domain + ": " + e.getMessage());
        }
        return serverCertificates;
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
    public static SSLSocketFactory getCustomSSLSocketFactory(String protocol, String[] sslEnabledProtocols, String[] sslCipherSuites, SecureRandom rand, TrustManager[] trustManagers, KeyManager[] keyManagers) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, trustManagers, rand);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        if (null != sslEnabledProtocols || null != sslCipherSuites)
            sslSocketFactory = new SSLUtils.CustomSSLSocketFactory(sslSocketFactory, sslEnabledProtocols, sslCipherSuites);
        return sslSocketFactory;
    }

    /**
     * 自定义 SSLSocketFactory
     */
    public static class CustomSSLSocketFactory extends javax.net.ssl.SSLSocketFactory {
        private final String[] _sslEnabledProtocols;
        private final String[] _sslCipherSuites;
        private final SSLSocketFactory _base;

        public CustomSSLSocketFactory(SSLSocketFactory base, String[] sslEnabledProtocols, String[] sslCipherSuites) {
            this._base = base;
            this._sslEnabledProtocols = sslEnabledProtocols != null ?  sslEnabledProtocols.clone() : null;

            if (null == sslCipherSuites || 0 == sslCipherSuites.length)
                _sslCipherSuites = base.getDefaultCipherSuites();
            else if (1 == sslCipherSuites.length && "ALL".equalsIgnoreCase(sslCipherSuites[0]))
                _sslCipherSuites = base.getSupportedCipherSuites();
            else
                _sslCipherSuites = sslCipherSuites.clone();
        }

        public String[] getDefaultCipherSuites() {
            return _base.getDefaultCipherSuites();
        }

        public String[] getSupportedCipherSuites() {
            return _base.getSupportedCipherSuites();
        }

        private SSLSocket customize(Socket s) {
            SSLSocket socket = (SSLSocket) s;
            if (null != _sslEnabledProtocols)
                socket.setEnabledProtocols(_sslEnabledProtocols);
            socket.setEnabledCipherSuites(_sslCipherSuites);
            return socket;
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            return customize(_base.createSocket(s, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return customize(_base.createSocket(host, port));
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            return customize(_base.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            return customize(_base.createSocket(host, port, localHost, localPort));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            return customize(_base.createSocket(address, port, localAddress, localPort));
        }
    }

    /**
     * 生成信任管理器
     * @return TrustManager[] 信任管理器数组
     */
    public static TrustManager[] getDefaultTrustManagers() {
        TrustManagerFactory trustManagerFactory;
        try {
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            throw new RuntimeException(e);
        }
        try {
            trustManagerFactory.init((KeyStore) null);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        return trustManagerFactory.getTrustManagers();
    }

    /**
     * 生成自定义信任管理器
     * @return TrustManager
     */
    public static TrustManager[] getCustomTrustManagers() {
        return new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
    }

    /**
     * 生成密钥管理器
     * @return KeyManager[] 密钥管理器数组
     */
    public static KeyManager[] getKeyManagers() {
        KeyManagerFactory keyManagerFactory;
        try {
            keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            keyManagerFactory.init(null, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
        return keyManagerFactory.getKeyManagers();
    }
}
