Shadowsocks-java
===========

shadowsocks-java is a lightweight tunnel proxy which can help you get through
 firewalls. It is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).
 
Only support TABLE encryption.

For Developers
-----------
Example:
    Shadowsocks sc = new Shadowsocks("example.com", 1234, "password");
    sc.start(8080);
    // Do other things
    sc.stop();

For Users
-----------
Recommended to use [more stable version](https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients).

    javac Shadowsocks.java
    java Shadowsocks <localPort> <serverAddr> <serverPort> <key>