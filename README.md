# pyssocks5
Toy [SOCKS5](https://tools.ietf.org/html/rfc1928) proxy local &amp; remote server with RSA Auth & AES encryption. Implemented with **Python 2.7**, depending on [pycrypto](https://github.com/dlitz/pycrypto) and [gevent](https://github.com/gevent/gevent).

### How to use

- generate 2048 bit rsa keys (default setting listed as below)

  > pyssocks5
  >
  > ​	|- keys
  >
  > ​		|- remote
  >
  > ​		|- remote.pub
  >
  > ​		|- local
  >
  > ​		|- local.pub

- run local proxy server `python local.py` ( `--help` for custom config info)

- run remote proxy server `python server.py`

- configure socks proxy setting.

  - e.g. on MacOS (tested on High Sierra v10.13.4) : 

    System Preference -> Network -> Advanced -> Proxies -> SOCKS Proxy

### References

- [felix021/ssocks5](https://github.com/felix021/ssocks5)
- [rushter/socks5](https://github.com/rushter/socks5)