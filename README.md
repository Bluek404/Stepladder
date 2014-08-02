Stepladder
==========

![渣渣一般的LOGO](http://img1.tuchuang.org/uploads/2014/07/绘图.svg)

梯子，当然是用来翻墙的

部分数据使用Golang专有的gob传输

使用socks5协议

使用tls加密

直接将需代理的域名传输到服务器，而不是IP。有效避免DNS污染

使用方法
-------

**客户端：**

  1. 点击右边的按钮打开客户端下载页面[![Gobuild Download](http://beta.gobuild.io/badge/github.com/Bluek404/Stepladder/client/download.png)](http://beta.gobuild.io/github.com/Bluek404/Stepladder/client)

  2. 先看一下你的系统是什么，如果不知道的话一般就是Windows。然后点击刚刚打开的页面右边你的系统的旁边的那个`download`按钮下载。

  3. 下载好后把文件解压到一个文件夹里

  4. 修改`client.ini`的配置

     >先双击打开`client.ini`文件

     ------------

     >`[client]`后面的配置修改：

     >把`EbzHvwg8BVYz9Rv3`修改为一个别的随机字符串（这个字符串是用来验证身份的，防止别人用你的代理服务器，类似密码）

     >端口`7071`一般不用修改，不过如果出现`listen tcp :7071: bind: address already in use`错误的话，那么就是端口冲突了。需要把`7071`修改为别的数字（推荐大于`10000`小于`65536`的数字）。如果你修改了这个端口，浏览器设置代理的时候请把`127.0.0.1:7071`后面的`7071`换成你设置的端口

     ------------

     >`[server]`后面的配置修改：

     >`127.0.0.1`请改为你的服务器地址（一般租服务器的时候人家都会告诉你的）

     >服务器端口`8081`，这个请和下面服务器设置的一样

  5. 把程序和`client.ini`放到你需要代理的客户端（你的电脑）

**服务端：**

  1. 点击右边按钮打开服务端下载页面[![Gobuild Download](http://beta.gobuild.io/badge/github.com/Bluek404/Stepladder/server/download.png)](http://beta.gobuild.io/github.com/Bluek404/Stepladder/server)

  2. 和上面的客户端一样的下载方式（请记得问一下你的服务器是什么系统，然后下载和服务器系统相同的）

  3. 下载好后把文件解压到一个文件夹里

  4. 修改`server.ini`的配置

     >先双击打开`server.ini`文件

     ------------

     >`[client]`后面的配置修改：

     >把`EbzHvwg8BVYz9Rv3`修改为和你客户端相同的字符串（不然客户端会提示“验证失败”）

     ------------

     >`[server]`后面的配置修改：

     >服务器端口`8081`，这个一般不用修改，除非提示`listen tcp :8081: bind: address already in use`，说明端口冲突了，才需要修改。请修改为大于`10000`小于`65536`的数字。记得客户端`[server]`后面的配置里要和这个相同

  5. 把程序和`server.ini`放到服务端（必须是不受GFW限制的服务器）

  6. 在服务器上创建证书  
  `openssl genrsa -out key.pem 2048`  
  `openssl req -new -x509 -key key.pem -out cert.pem -days 3650`

  7. 然后在防火墙上开启8081端口（如果你刚刚修改了端口，请开启相应的端口，开启方法可以问你的服务器提供商）

运行服务端和客户端

设置浏览器的socks5代理为`127.0.0.1:7071`就可以啦（后面的端口依据你上面修改的配置而定）

如果还有什么不会的话可以在[这里](https://github.com/Bluek404/Stepladder/issues)提交问题，或者加我QQ799669332（请备注`Stepladder问题`）

TODO
----

~~添加验证系统（用户名+密码或者直接用key）~~

~~添加配置文件~~

可选的图形界面

