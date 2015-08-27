# mod_process_security [![Build Status](https://travis-ci.org/matsumoto-r/mod_process_security.svg?branch=master)](https://travis-ci.org/matsumoto-r/mod_process_security)
This module is a suEXEC module for CGI and DSO. Improvement of mod_ruid2(vulnerability) and mod_suexec(performance).

See also http://blog.matsumoto-r.jp/?p=1972

- matsumoto_r (MATSUMOTO, Ryosuke) Sep 2011 in Japan
    - Academic Center for Computing and Media Studies, Kyoto University
    - Okabe Lab
    - email: matsumoto_r at net.ist.i.kyoto-u.ac.jp
    - Date     2011/11/11
    - Version  1.00

- change log
```
 2011/11/11 1.00 matsumoto_r first release
```

## How To Compile
- build
```
apxs -i -c -l cap mod_process_security.c
```

- Add to httpd.conf or conf.d/process_security.conf
```
LoadModule process_security_module   modules/mod_process_security.so
PSExAll On
```

## How To Use

* Set Enable All Extensions On. (default Off)
```
PSExAll On
```

* Set Enable ALL CGI Extensions On. (default Off)
```
PSExCGI On
```

* [Optional] Set Enable Custom Extensions. (unset PSExAll)
```
PSExtensions .php .pl .py
```

* [Optional] Set Enable Custom Handlers. (unset PSExAll)
```
PSHandlers application/x-httpd-php hoge-script
```

* [Optional] Set Ignore Custom Extensions.
```
# .html and .css were ignored
PSExAll On
PSIgnoreExtensions .html .css
```

* [Optional] Minimal uid and gid. (default uid:100 gid:100)
```
PSMinUidGid 200 200
```

* [Optional] Default uid and gid. (default uid:48 gid:48)
```
PSDefaultUidGid
```

* [Optional] Enable run with root permission (default Off)
```
PSRootEnable On
```
