Stepladder
==========

>梯子是一种用于翻墙的工具

数据使用Golang专有的gob编码传输，并用TLS协议加密

客户端使用socks5协议连接

可直接将需代理的域名传输到服务器，而不是IP。有效避免DNS污染

下载
----

[![download](https://img.shields.io/badge/Download-Stepladder--linux--32-green.svg?style=flat-square)](https://github.com/Bluek404/Stepladder/releases/download/1.0.0/Stepladder-linux-32.tar.gz)
[![download](https://img.shields.io/badge/Download-Stepladder--linux--64-green.svg?style=flat-square)](https://github.com/Bluek404/Stepladder/releases/download/1.0.0/Stepladder-linux-64.tar.gz)
[![download](https://img.shields.io/badge/Download-Stepladder--linux--arm-green.svg?style=flat-square)](https://github.com/Bluek404/Stepladder/releases/download/1.0.0/Stepladder-linux-arm.tar.gz)

[![download](https://img.shields.io/badge/Download-Stepladder--mac--32-blue.svg?style=flat-square)](https://github.com/Bluek404/Stepladder/releases/download/1.0.0/Stepladder-mac-32.tar.gz)
[![download](https://img.shields.io/badge/Download-Stepladder--mac--64-blue.svg?style=flat-square)](https://github.com/Bluek404/Stepladder/releases/download/1.0.0/Stepladder-mac-64.tar.gz)

[![download](https://img.shields.io/badge/Download-Stepladder--windows--32-red.svg?style=flat-square)](https://github.com/Bluek404/Stepladder/releases/download/1.0.0/Stepladder-windows-32.tar.gz)
[![download](https://img.shields.io/badge/Download-Stepladder--windows--64-red.svg?style=flat-square)](https://github.com/Bluek404/Stepladder/releases/download/1.0.0/Stepladder-windows-64.tar.gz)

使用方法
-------

> **请再也不要问我没有服务器怎么办了！这个程序必须要有服务器才行！（也别问我服务器是什么！）**

先从上方根据你的系统下载程序，并解压

**客户端：**

  1. 打开`client`文件夹

  2. 修改`client.ini`的配置

     > 用任何编辑器打开`client.ini`文件

     ------------

     > `[client]`后面的配置修改：

     > 把`eGauUecvzS05U5DIsxAN4n2hadmRTZGBqNd2zsCkrvwEBbqoITj36mAMk4Unw6Pr`修改为一个别的随机字符串（这个字符串是用来验证身份的，防止别人用你的代理服务器，类似密码）

     > 端口`7071`一般不用修改，不过如果出现`listen tcp :7071: bind: address already in use`错误的话，那么就是端口冲突了。
     需要把`7071`修改为别的数字（推荐大于`10000`小于`65536`的数字）。
     如果你修改了这个端口，浏览器设置代理的时候请把`127.0.0.1:7071`后面的`7071`换成你设置的端口

     ------------

     > `[server]`后面的配置修改：

     > `localhost`请改为你的服务器地址（一般租服务器的时候人家都会告诉你的）

     > `8081`为服务器端口，这个请和下面服务器设置的一样

  3. 把程序和`client.ini`放到需要代理的客户端（你的电脑）

**服务端：**

  1. 打开`server`文件夹

  2. 修改`server.ini`的配置

     > 用任何编辑器打开`server.ini`文件

     ------------

     > `[client]`后面的配置修改：

     >把`eGauUecvzS05U5DIsxAN4n2hadmRTZGBqNd2zsCkrvwEBbqoITj36mAMk4Unw6Pr`修改为和你客户端相同的字符串（不然客户端会提示“验证失败”）

     ------------

     > `[server]`后面的配置修改：

     > 服务器端口`8081`，这个一般不用修改，除非提示`listen tcp :8081: bind: address already in use`，说明端口冲突了，才需要修改。
     请修改为大于`10000`小于`65536`的数字。记得客户端`[server]`后面的配置要和这个相同

  3. 把程序和`server.ini`放到服务端（必须是墙外服务器）

  4. 在服务器上创建证书  
  `openssl genrsa -out key.pem 2048`  
  `openssl req -new -x509 -key key.pem -out cert.pem -days 3650`
  > 注意：在执行第二步生成证书的时候，请把`Common Name`填写为你服务器的域名（可以使用免费域名、二级域名、hosts文件里设置的域名，只要是个域名不是IP就行），其他可以随便填。以及千万不要把`key.pem`给别人

  5. 在防火墙上开启`8081`端口（如果你刚刚修改了端口，请开启相应的端口，开启方法可以问你的服务器提供商）

  6. 把生成的`cert.pem`文件放到**客户端**的文件夹里

运行服务端和客户端

设置浏览器的socks5代理为`127.0.0.1:7071`就可以啦（后面的端口依据你上面修改的配置而定）

如果还有什么不会的话可以在[这里](https://github.com/Bluek404/Stepladder/issues)提交问题，或者发送邮件到<i@bluek404.net>
