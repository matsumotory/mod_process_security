# mod_process_security RPM Packaging

[![Build Status](https://github.com/matsumotory/mod_process_security/workflows/test/badge.svg?branch=master)](https://github.com/matsumotory/mod_process_security/actions?query=workflow%3Atest)

## Install an RPM package

- [Download](https://github.com/matsumotory/mod_process_security/releases)
- `yum install mod_process_security-x.y.z-n.elx.x86_64.rpm`
- Edit `/etc/httpd/conf.d/mod_process_security.conf`
- `systemctl restart httpd.service`

## Usage

```
Usage:
    build [-d] [-h] [-t BUILD_TAG] BUILD_IMAGE_NAME

    Options:
        -d Debug mode.
        -t Build target tag (default: latest)
            e.g.: v1.0.0, v1.0.0-1, SHA_HASH

    Build for RHEL/AlmaLinux/Rocky Linux 10:
        build -t vx.y.z almalinux:10

    Build for RHEL/AlmaLinux/Rocky Linux 9:
        build -t vx.y.z almalinux:9

    Build for RHEL/AlmaLinux/Rocky Linux 8:
        build -t vx.y.z almalinux:8
```

## Build RPM Packages with Docker

You can build RPM packages in Docker.

```
./redhat/build
```

- Debug shell

```
./redhat/build -d
/pkg/build-rpm /pkg/rpmbuild mod_process_security.spec
```

## Release tag

e.g.:

```
git tag -a vx.y.z -m "mod_process_security vx.y.z"
git push origin refs/tags/vx.y.z
```

