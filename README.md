Stepladder
==========

![渣渣一般的LOGO](http://img1.tuchuang.org/uploads/2014/07/绘图.svg)

梯子，当然是用来翻墙的

部分数据使用Golang专有的gob传输

使用socks5协议

使用tls加密

使用方法
-------

**客户端：**

  1. 点击按钮下载客户端[![Gobuild Download](http://beta.gobuild.io/badge/github.com/Bluek404/Stepladder/client/download.png)](http://beta.gobuild.io/github.com/Bluek404/Stepladder/client)

  2. 修改`client.ini`的配置

  3. 把程序和`client.ini`放到你需要代理的客户端（你的电脑）

**服务端：**

  1. 点击按钮下载服务端[![Gobuild Download](http://beta.gobuild.io/badge/github.com/Bluek404/Stepladder/server/download.png)](http://beta.gobuild.io/github.com/Bluek404/Stepladder/server)

  4. 修改`server.ini`的配置

  2. 把程序和`server.ini`放到服务端（必须是不受GFW限制的服务器）

  3. 在服务器上创建证书  
  `openssl genrsa -out key.pem 2048`  
  `openssl req -new -x509 -key key.pem -out cert.pem -days 3650`

  5. 然后在防火墙上开启8081端口（当然也可以在`server.ini`里修改为其他端口）

运行服务端和客户端

设置浏览器的socks5代理为`127.0.0.1:7071`就可以啦（后面的端口依据你的配置而定）

TODO
----

~~添加验证系统（用户名+密码或者直接用key）~~

~~添加配置文件~~

可选的图形界面
