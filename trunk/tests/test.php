<?php
// $Id$

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
