# CA 与自签名

## 制作 RSA 私钥

```sh
openssl genrsa -out ca.key 2048
```

## 制作CA公钥/根证书

```sh
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt
```

# 服务器端证书

## 制作服务器私钥

```sh
openssl genrsa -out server.pem 1024
openssl rsa -in server.pem -out server.key
```



## 生成签发请求

```sh
openssl req -new -key server.pem -out server.csr
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
Common Name (e.g. server FQDN or YOUR name) []:nginx.ssl.server
Email Address []:admin@ubattery.cn

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
```

## 用CA签发证书

```sh
openssl x509 -req -sha256 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -out server.crt
```

# 客户端证书

## 制作私钥

```sh
openssl genrsa -out client.pem 1024
openssl rsa -in client.pem -out client.key
```

## 生成签发请求

```sh
openssl req -new -key client.pem -out client.csr
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
Locality Name (eg, city) []:ShengZhen
Organization Name (eg, company) [Internet Widgits Pty Ltd]:ZYKJ
Organizational Unit Name (eg, section) []:HQ
Common Name (e.g. server FQDN or YOUR name) []:nginx.ssl.server
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
server{
	listen 443 ssl;
	server_name  nginx.ssl.server
	access_log off;
	
	ssl on;
	ssl_certificate /etc/nginx/ssl/server.crt;
	ssl_certificate_key /etc/nginx/ssl/server.key
	ssl_client_certificate /etc/nginx/ssl/ca.crt;
	ssl_verify_client on;
	
	location / {
		proxy_pass http://www.baidu.com;
	}
}
```

