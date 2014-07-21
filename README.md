Stepladder
==========

![渣渣一般的LOGO](http://img1.tuchuang.org/uploads/2014/07/绘图.svg)

梯子，当然是用来翻墙的

使用方法
-------

先修改客户端中的`127.0.0.1`为你的服务器地址

然后`go build client.go`即可

服务端需要先在服务器上创建证书

```shell
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 3650
```

然后在防火墙上开启8081端口（当然也可以在源码里修改为其他端口）

然后`go build server.go`就行

TODO
----

添加验证系统（用户名+密码或者直接用key）

添加配置文件

可选的图形界面
