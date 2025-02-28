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
     * @param host 检测的域名
     * @param readTimeout 超时
     * @param connectTimeout 连接超时
     * @param sslSocketFactory SSLSocketFactory
     * @return 创建SSLSocket
     * @throws IOException IOException
     */
    public static SSLSocket createSSLSocket(InetSocketAddress address, String host, int port, int readTimeout, int connectTimeout, SSLSocketFactory sslSocketFactory) throws IOException {
        Socket sock = new Socket();
        sock.setSoTimeout(readTimeout);
        sock.connect(address, connectTimeout);
        return (SSLSocket) sslSocketFactory.createSocket(sock, host, port, true);
    }

    public static Certificate[] getCertificatesWithoutValidation(String domain, int port) {
        X509Certificate[] serverCertificates;
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            }, new java.security.SecureRandom());
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
     * 自定义 SSLSocketFactory
     */
    public static class CustomSSLSocketFactory extends javax.net.ssl.SSLSocketFactory {
        private final String[] _sslEnabledProtocols;
        private final String[] _sslCipherSuites;
        private final SSLSocketFactory _base;

        public CustomSSLSocketFactory(SSLSocketFactory base, String[] sslEnabledProtocols, String[] sslCipherSuites) {
            _base = base;
            if (null == sslEnabledProtocols)
                _sslEnabledProtocols = null;
            else
                _sslEnabledProtocols = sslEnabledProtocols.clone();
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
    public static TrustManager[] getTrustManagers(boolean isCustomized) {
        if (!isCustomized) {
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
        } else {
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
