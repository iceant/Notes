# CA 与自签名

## 制作 RSA 私钥

```sh
openssl genrsa -out ca.key 4096
```

## 制作CA公钥/根证书

```sh
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/C=CN/ST=GD/L=SZ/O=ZYKJ/OU=HQ/CN=ubattery.net/emailAddress=pizer.chen@gmail.com"
```

```text
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:CN
State or Province Name (full name) [Some-State]:GuangDong
Locality Name (eg, city) []:ShenZhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:ZYKJ
Organizational Unit Name (eg, section) []:HQ
Common Name (e.g. server FQDN or YOUR name) []:nginx.ssl
Email Address []:
```



# 服务器端证书

## 制作服务器私钥

```sh
openssl genrsa -out server.pem 2048
openssl rsa -in server.pem -out server.key
```



## 生成签发请求

```sh
openssl req -new -key server.pem -out server.csr -subj "/C=CN/ST=GD/L=SZ/O=ZYKJ/OU=HQ/CN=server.ubattery.net/emailAddress=pizer.chen@gmail.com"
```

```text
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:CN
State or Province Name (full name) [Some-State]:GuangDong
Locality Name (eg, city) []:ShenZhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:ZYKJ
Organizational Unit Name (eg, section) []:HQ
Common Name (e.g. server FQDN or YOUR name) []:localhost
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

## 用CA签发证书

```sh
openssl x509 -req -sha256 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -out server.crt
```

# 客户端证书

## 制作私钥

```sh
openssl genrsa -out client.pem 2048
openssl rsa -in client.pem -out client.key
```

## 生成签发请求

```sh
openssl req -new -key client.pem -out client.csr -subj "/C=CN/ST=GD/L=SZ/O=ZYKJ/OU=HQ/CN=client.ubattery.net/emailAddress=pizer.chen@gmail.com"
```

```text
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:CN
State or Province Name (full name) [Some-State]:GuangDong
Locality Name (eg, city) []:ShenZhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:ZYKJ
Organizational Unit Name (eg, section) []:HQ
Common Name (e.g. server FQDN or YOUR name) []:nginx.ssl.client
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

## 用 CA 签发

```sh
openssl x509 -req -sha256 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -out client.crt
```

# 配置 Nginx 

```conf
server {
    listen       443 ssl;
    listen  [::]:443 ssl;
    server_name  localhost;

    access_log /var/log/nginx/user.log;
    error_log /var/log/nginx/user.error;

    #charset koi8-r;
    #access_log  /var/log/nginx/host.access.log  main;

    ssl_certificate /etc/ssl/server.crt;
    ssl_certificate_key /etc/ssl/server.key;
    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client on;
    ssl_session_timeout 5m;
    ssl_protocols SSLv2 SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    location /ssl/ {
        proxy_pass http://127.0.0.1:8866/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
    }


    #error_page  404              /404.html;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }

    # proxy the PHP scripts to Apache listening on 127.0.0.1:80
    #
    #location ~ \.php$ {
    #    proxy_pass   http://127.0.0.1;
    #}

    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    #location ~ \.php$ {
    #    root           html;
    #    fastcgi_pass   127.0.0.1:9000;
    #    fastcgi_index  index.php;
    #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
    #    include        fastcgi_params;
    #}

    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all;
    #}
}
```

## 验证 

```sh
curl -k --cacert ca.crt --cert client.crt --key client.key --tlsv1.2 https://localhost:8443
```

如果客户端证书需要密码，在crt文件后面使用冒号(:)密码的方式访问

```sh
curl -v -s -k --key client.key --cert client.crt:12345 --tlsv1.2 https://localhost:8443
```

## Socket Stream 模式

### nginx.conf

```conf
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    use epoll;
    worker_connections  65535;
}

stream {
    include /etc/nginx/conf.d/*.stream;
}
```

### conf.d/gb32960.stream

```conf
upstream gb32960{
    hash $remote_addr consistent;
    server 192.168.0.196:32960;
    server 192.168.0.196:32961;
    server 192.168.0.196:32962;
}

log_format proxy '$remote_addr [$time_local] '
                 '$protocol $status $bytes_sent $bytes_received '
                 '$session_time "$upstream_addr" '
                 '"$upstream_bytes_sent" "$upstream_bytes_received" "$upstream_connect_time"';

access_log /var/log/nginx/tcp-access.log proxy ;
open_log_file_cache off;

server {
    listen       443 ssl;
    listen  [::]:443 ssl;

    proxy_connect_timeout 1s;
    proxy_timeout 3s;
    proxy_socket_keepalive on;
    proxy_pass gb32960;
    
    ssl_certificate /etc/ssl/server.crt;
    ssl_certificate_key /etc/ssl/server.key;
    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client on;
    ssl_session_timeout 5m;
    ssl_protocols SSLv2 SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;
}
```

### 重启Nginx

重启生效

# Java 客户端使用

## 生成 p12 格式证书

```sh
openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12
```



## 使用 Java KeyTool 导入

```sh
keytool -import -alias nginx-ssl-server -keystore cacerts -file server.crt
```

```text
输入密钥库口令:
再次输入新口令:
所有者: CN=localhost, OU=HQ, O=ZYKJ, L=ShenZhen, ST=GuangDong, C=CN
发布者: CN=nginx.ssl, OU=HQ, O=ZYKJ, L=ShenZhen, ST=GuangDong, C=CN
序列号: 3bf6efedc4acaa2231f0ceeddfae49876ec1d04a
生效时间: Fri Mar 26 10:23:49 CST 2021, 失效时间: Mon Mar 24 10:23:49 CST 2031
证书指纹:
         SHA1: 16:AE:C6:F5:1A:1D:76:52:6D:4E:86:8F:27:30:96:24:3D:F2:78:F4
         SHA256: AE:F4:CA:17:FB:38:E5:A2:D7:0C:92:DD:E1:5D:28:C8:E6:DD:21:5C:2B:C5:24:08:91:73:0C:B8:39:C0:F7:1F
签名算法名称: SHA256withRSA
主体公共密钥算法: 2048 位 RSA 密钥
版本: 1
是否信任此证书? [否]:  Y
证书已添加到密钥库中
```

## 客户端代码

```java

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

public class SSLClientWithHttpClient {
    private SSLSocketFactory sslFactory = null;
    private SSLSocketFactory getSSLFactory() throws Exception {
        if (sslFactory == null) {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            TrustManager[] tm = { new MyX509TrustManager() };

            KeyStore truststore = KeyStore.getInstance("JKS");
            truststore.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("ssl/client.p12"), "123456".toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(truststore, "123456".toCharArray());
            sslContext.init(kmf.getKeyManagers(), tm, new java.security.SecureRandom());
            sslFactory = sslContext.getSocketFactory();
        }
        return sslFactory;
    }

    private HttpURLConnection doHttpRequest(String requestUrl, String method, String body, Map<String, String> header) throws Exception {
        HttpURLConnection conn;

        if (method == null || method.length() == 0 ) {
            method = "GET";
        }
        if ("GET".equals(method) && body != null && ! body.isEmpty()) {
            requestUrl = requestUrl + "?" + body;
        }

        URL url = new URL(requestUrl);
        conn = (HttpURLConnection) url.openConnection();

        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestMethod(method);

        if (requestUrl.matches("^(https?)://.*$")){
            ((HttpsURLConnection) conn).setSSLSocketFactory(this.getSSLFactory());
        }

        if (header != null) {
            for (String key : header.keySet()) {
                conn.setRequestProperty(key, header.get(key));
            }
        }

        if (body != null && ! body.isEmpty()) {
            if (!method.equals("GET") ) {
                OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
                wr.write(body);
                wr.close();
            }
        }
        conn.connect();
        return conn;
    }

    public int getResponseCode(HttpURLConnection connection) throws IOException {
        return connection.getResponseCode();
    }

    public String getResponseBodyAsString(HttpURLConnection connection) throws Exception {
        BufferedReader reader = null;
        if (connection.getResponseCode() == 200) {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
        }

        StringBuffer buffer = new StringBuffer();
        String line=null;
        while ((line = reader.readLine()) != null) {
            buffer.append(line);
        }
        return buffer.toString();
    }

    class MyX509TrustManager implements X509TrustManager {
        private X509TrustManager sunJSSEX509TrustManager;

        MyX509TrustManager() throws Exception {
            // create a "default" JSSE X509TrustManager.
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("ssl/client.p12"), "123456".toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
            tmf.init(ks);
            TrustManager tms[] = tmf.getTrustManagers();

            /*
             * Iterate over the returned trustmanagers, look for an instance of
             * X509TrustManager. If found, use that as our "default" trust manager.
             */
            for (int i = 0; i < tms.length; i++) {
                if (tms[i] instanceof X509TrustManager) {
                    sunJSSEX509TrustManager = (X509TrustManager) tms[i];
                    return;
                }
            }
            throw new Exception("Couldn't initialize");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                sunJSSEX509TrustManager.checkClientTrusted(chain, authType);
            } catch (CertificateException excep) {
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                sunJSSEX509TrustManager.checkServerTrusted(chain, authType);
            } catch (CertificateException excep) {
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return sunJSSEX509TrustManager.getAcceptedIssuers();
        }
    }

    public static void main(String[] args) throws Exception{
        SSLClientWithHttpClient client = new SSLClientWithHttpClient();
        HttpURLConnection connection = client.doHttpRequest("https://localhost:8443", "GET", null, null);
        int responseCode = client.getResponseCode(connection);
        String responseBody = client.getResponseBodyAsString(connection);
        connection.disconnect();
        System.out.println("response code=" + responseCode + ", body=[" + responseBody + "]");
    }
}
```

# Netty 客户端

```java
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyStore;

public class SSLContextUtil{
    public static SSLContext getSSLContextForClient() throws Exception{
        SSLContext sslContext = SSLContext.getInstance("SSL");
        TrustManager[] tm = { new MyX509TrustManager() };

        KeyStore truststore = KeyStore.getInstance("JKS");
        truststore.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("ssl/client.p12"), "123456".toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(truststore, "123456".toCharArray());
        sslContext.init(kmf.getKeyManagers(), tm, new java.security.SecureRandom());
        return sslContext;
    }
}
```

```java
public void connect(String ip , int port){
    EventLoopGroup group = new NioEventLoopGroup();
    try{
        Bootstrap strap = new Bootstrap();
        strap.group(group)
            .channel(NioSocketChannel.class)
            .option(ChannelOption.TCP_NODELAY, true)
            .option(ChannelOption.SO_KEEPALIVE , true)
            .handler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel socketChannel) throws Exception {
                    SSLEngine engine = SSLContextUtil.getSSLContextForClient().createSSLEngine();
                    engine.setUseClientMode(true);
                    
                    ChannelPipeline pieple = socketChannel.pipeline() ;
                    pieple.addLast(new CarDataClientHandler()); // 这是自己写的协议处理
                    pieple.addFirst("ssl", new SslHandler(engine));
                }
            });
        SocketAddress address = new InetSocketAddress(ip, port);
        final ChannelFuture future = strap.connect(address).sync();
        channel = future.awaitUninterruptibly().channel();
        System.out.println("连接成功， channel =" + channel.remoteAddress());
    }catch(Exception e ){
        e.printStackTrace();
        group.shutdownGracefully() ;
    }finally{

    }
}
```

## 支持 IP 访问 HTTPS

```java
package cn.ubattery;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

public class SSLClientWithHttpClient {
    static final String KEYSTORE = "ssl/client.p12";
    static final String KEYPASS = "123456";

    private SSLSocketFactory sslFactory = null;
    private SSLSocketFactory getSSLFactory() throws Exception {
        if (sslFactory == null) {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            TrustManager[] tm = { new MyX509TrustManager(KEYSTORE) };

            KeyStore truststore = KeyStore.getInstance("JKS");
            truststore.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(KEYSTORE), KEYPASS.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(truststore, KEYPASS.toCharArray());
            sslContext.init(kmf.getKeyManagers(), tm, new java.security.SecureRandom());
            sslFactory = sslContext.getSocketFactory();
        }
        return sslFactory;
    }

    private HttpURLConnection doHttpRequest(String requestUrl, String method, String body, Map<String, String> header) throws Exception {
        HttpURLConnection conn;

        if (method == null || method.length() == 0 ) {
            method = "GET";
        }
        if ("GET".equals(method) && body != null && ! body.isEmpty()) {
            requestUrl = requestUrl + "?" + body;
        }

        URL url = new URL(requestUrl);
        conn = (HttpURLConnection) url.openConnection();

        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestMethod(method);

        if (requestUrl.matches("^(https?)://.*$")){
            ((HttpsURLConnection) conn).setSSLSocketFactory(this.getSSLFactory());
            
            // *******************************
            // ************* 新增 *************
            // *******************************
            ((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String s, SSLSession sslSession) {
                    return true;
                }
            });
        }

        if (header != null) {
            for (String key : header.keySet()) {
                conn.setRequestProperty(key, header.get(key));
            }
        }

        if (body != null && ! body.isEmpty()) {
            if (!method.equals("GET") ) {
                OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
                wr.write(body);
                wr.close();
            }
        }
        conn.connect();
        return conn;
    }

    public int getResponseCode(HttpURLConnection connection) throws IOException {
        return connection.getResponseCode();
    }

    public String getResponseBodyAsString(HttpURLConnection connection) throws Exception {
        BufferedReader reader = null;
        if (connection.getResponseCode() == 200) {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
        }

        StringBuffer buffer = new StringBuffer();
        String line=null;
        while ((line = reader.readLine()) != null) {
            buffer.append(line);
        }
        return buffer.toString();
    }

    class MyX509TrustManager implements X509TrustManager {
        private X509TrustManager sunJSSEX509TrustManager;

        MyX509TrustManager(String path) throws Exception {
            // create a "default" JSSE X509TrustManager.
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(path), KEYPASS.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
            tmf.init(ks);
            TrustManager tms[] = tmf.getTrustManagers();

            /*
             * Iterate over the returned trustmanagers, look for an instance of
             * X509TrustManager. If found, use that as our "default" trust manager.
             */
            for (int i = 0; i < tms.length; i++) {
                if (tms[i] instanceof X509TrustManager) {
                    sunJSSEX509TrustManager = (X509TrustManager) tms[i];
                    return;
                }
            }
            throw new Exception("Couldn't initialize");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                sunJSSEX509TrustManager.checkClientTrusted(chain, authType);
            } catch (CertificateException excep) {
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                sunJSSEX509TrustManager.checkServerTrusted(chain, authType);
            } catch (CertificateException excep) {
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return sunJSSEX509TrustManager.getAcceptedIssuers();
        }
    }

    public static void main(String[] args) throws Exception{
        SSLClientWithHttpClient client = new SSLClientWithHttpClient();
        HttpURLConnection connection = client.doHttpRequest("https://192.168.0.196:8443", "POST", null, null);
        int responseCode = client.getResponseCode(connection);
        String responseBody = client.getResponseBodyAsString(connection);
        connection.disconnect();
        System.out.println("response code=" + responseCode + ", body=[" + responseBody + "]");
    }
}
```



# 常用词汇

- 证书授权机构 (Certification Authority, CA)
- 证书签名请求 (CSR)

