# Office To PDF

> Converts office files to PDF files 

This library is a Rust wrapper around [unoserver](https://github.com/unoconv/unoserver) which uses [LibreOffice](https://www.libreoffice.org/) to
convert the office files to PDF.

Supports handling remote unoserver instances and load balancing traffic between multiple unoserver instances

## Installation

Install LibreOffice, Python 3, and Python 3 pip (Command for Debian, apt package manager. Adjust for your distro):

```sh
sudo apt-get install -y libreoffice python3 python3-pip
```


Install unoserver pip module

```sh
sudo pip install unoserver
```