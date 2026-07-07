![abphish logo](https://raw.github.com/abphish/abphish/master/static/images/abphish_purple.png)

Abphish
=======

![Build Status](https://github.com/abphish/abphish/workflows/CI/badge.svg) [![GoDoc](https://godoc.org/github.com/abphish/abphish?status.svg)](https://godoc.org/github.com/abphish/abphish)

Abphish: Open-Source Phishing Toolkit

[Abphish](https://getabphish.com) is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.

### Install

Installation of Abphish is dead-simple - just download and extract the zip containing the [release for your system](https://github.com/abphish/abphish/releases/), and run the binary. Abphish has binary releases for Windows, Mac, and Linux platforms.

### Building From Source
**If you are building from source, please note that Abphish requires Go v1.10 or above!**

To build Abphish from source, simply run ```git clone https://github.com/abphish/abphish.git``` and ```cd``` into the project source directory. Then, run ```go build```. After this, you should have a binary called ```abphish``` in the current directory.

### Docker
You can also use Abphish via the official Docker container [here](https://hub.docker.com/r/abphish/abphish/).

### Setup
After running the Abphish binary, open an Internet browser to https://localhost:3333 and login with the default username and password listed in the log output.
e.g.
```
time="2020-07-29T01:24:08Z" level=info msg="Please login with the username admin and the password 4304d5255378177d"
```

Releases of Abphish prior to v0.10.1 have a default username of `admin` and password of `abphish`.

### Documentation

Documentation can be found on our [site](http://getabphish.com/documentation). Find something missing? Let us know by filing an issue!

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let us know! Please don't hesitate to [file an issue](https://github.com/abphish/abphish/issues/new) and we'll get right on it.

### License
```
Abphish - Open-Source Phishing Framework

The MIT License (MIT)

Copyright (c) 2013 - 2020 Jordan Wright

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software ("Abphish Community Edition") and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
