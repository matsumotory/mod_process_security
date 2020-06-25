# mod_process_security RPM Packaging

[![Build Status](https://github.com/matsumotory/mod_process_security/workflows/test/badge.svg?branch=master)](https://github.com/matsumotory/mod_process_security/actions?query=workflow%3Atest)

RPM Packaging for [mod_process_security](https://github.com/matsumotory/mod_process_security).

## Install an RPM package

- [Download](https://github.com/matsumotory/mod_process_security/releases)
- `yum install mod_process_security-x.y.z-n.elx.x86_64.rpm`
- Edit `/etc/httpd/conf.d/mod_process_security.conf`
- `systemctl restart httpd.service`

## Usage

```
Usage:
    build [-d] [-h] BUILD_IMAGE_NAME

    Options:
        -d Debug mode.

    Build for CentOS 8:
        build -i centos:8

    Build for CentOS 7:
        build -i centos:7
```

## Build RPM Packages with Docker

You can build RPM packages in Docker.

```
cd redhat/
./build
```

- Debug shell

```
cd redhat/
./build -d
/pkg/build-rpm /pkg/rpmbuild mod_process_security.spec
```

## Release tag

e.g.:

```
git tag -a vx.y.z-n -m "vx.y.z-n"
git push origin refs/tags/vx.y.z-n
```

