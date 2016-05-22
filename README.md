# WHOIS pear package
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/OOPS-ORG-PHP/WHOIS/master/LICENSE)

### Description

Whois gateway PHP class

1. support IP address lookup
2. print result with auto recursion

### License

BSD 2 clause

### Reference

http://pear.oops.org/docs/WHOIS/WHOIS.html

reference is written by Korean. If you can't read korean, use [google translator](https://translate.google.com/translate?sl=ko&tl=en&js=y&prev=_t&hl=ko&ie=UTF-8&u=http%3A%2F%2Fpear.oops.org%2Fdocs%2FWHOIS%2FWHOIS.html&edit-text=).

### Installation

```shell
[root@host ~] pear channel-discover pear.oops.org
Adding Channel "pear.oops.org" succeeded
Discovery of channel "pear.oops.org" succeeded
[root@host ~] pear install oops/WHOIS
```

### Dependency
 * PHP >= 5.3.0
 * Pear packages 
  * [myException](https://github.com/OOPS-ORG-PHP/myException) >= 1.0.1

### Sample codes

```php
<?php
require_once 'WHOIS.php';
set_error_handler ('myException::myErrorHandler');

try {
    $w = new oops\WHOIS;
    $whois = $w->lookup ($argv[1]);

    print_r ($whois);

} catch ( myException $e ) {
    echo $e->Message () . "\n";
    print_r ($e->TraceAsArray ());
}
?>
```
