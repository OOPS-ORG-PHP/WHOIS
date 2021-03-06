<?php
/**
 * Project: oops\WHOIS :: WHOIS php gateway
 * File:    WHOIS.php<br>
 * Dependency:
 *   - {@link http://pear.oops.org/docs/li_myException.html oops/myException}
 *
 * oops\WHOIS class는 php로 작성된 WHOIS gateway이며, IP 주소 lookup을 지원하며
 * 자동으로 recursion을 하여 최종 결과물을 출력한다.
 *
 * @category  Networking
 * @package   WHOIS
 * @author    JoungKyun.Kim <http://oops.org>
 * @copyright (c) 2018, OOPS.org
 * @license   BSD License
 * @link      https://github.com/OOPS-ORG-PHP/WHOIS
 * @since     File available since release 1.0.0
 * @example   WHOIS/tests/test.php WHOIS pear package 예제 코드
 * @filesource
 */

namespace oops;

/**
 * import myException class
 */
require_once 'myException.php';

/**
 * oops\WHOIS pear pcakge의 main class
 *
 * oops\WHOIS class는 php로 작성된 WHOIS gateway이며, IP 주소 lookup을 지원하며
 * 자동으로 recursion을 하여 최종 결과물을 출력한다.
 *
 * @package   WHOIS
 * @author    JoungKyun.Kim <http://oops.org>
 * @copyright (c) 2018, OOPS.org
 * @license   BSD License
 * @link      https://github.com/OOPS-ORG-PHP/WHOIS
 * @since     File available since release 1.0.0
 * @example   WHOIS/tests/test.php WHOIS pear 예제 코드
 */
Class WHOIS {
	// {{{ properities
	/**#@+
	 * @access private
	 */
	/**
	 * infinite recursion 방지
	 * @var string
	 */
	private $pnext = '';
	/**
	 * Next whois server
	 * @var string
	 */
	private $next = '';
	/**
	 * Allow ip search flags
	 * @var array
	 */
	private $allows = array ('kr', 'jp');

	private $debug = false;
	/**#@-*/
	/**
	 * recursion 기능 동작 flag
	 * @access public
	 * @var boolean
	 */
	public $recurse = false;
	// }}}

	// {{{ +-- public lookup ($domain, $server = '', $timeout = 5)
	/**
	 * 도메인 또는 IP 주소를 lookup 한다.
	 *
	 * 두번째 파라미터 Whois server를 지정하면, 자동 recursion 기능이 off가
	 * 된다. 만약 whois server를 지정하더라도 recursion이 동작하기를
	 * 바란다면 WHOIS::$recurse 의 값을 true로 설정하고 WOHIS::lookup을
	 * 호출하면 된다.
	 *
	 * @access public
	 * @return stdClass 최종 요청한 whois server와 결과를 stdClass로 반환
	 *         - server 최종 요청을 처리한 whois server
	 *         - desc   lookup 내용
	 * @param  string $domain   검색할 도메인
	 * @param  string $server   (optional) WHOIS server
	 * @param  string $timeout  (optional) connection timeout [default 5sec] 
	 */
	function lookup ($domain, $server = '', $timeout = 5) {
		$this->pnext = $this->next = '';

		if ( ! strlen (trim ($domain)) ) {
			return (object) array (
				'server' => '',
				'desc'   => 'No Domains'
			);
		}
		$domain = trim ($domain);

		if ( ! $server ) {
			$server = $this->detect ($domain);
			$this->recurse = true;
		}

		$buf = $this->query ($server, $domain, $timeout);

		return (object) array (
			'server' => $server,
			'desc'   => trim ($buf)
		);
	}
	// }}}

	// {{{ +-- private query ($server, $domain, $timeout = 5)
	private function query (&$server, $domain, $timeout = 5) {
		if ( ! preg_match ('/:[0-9]+/', $server) )
			$server .= ':43';

		$sock = stream_socket_client (
			'tcp://' . $server, $errno,
			$errstr, $timeout, STREAM_CLIENT_CONNECT
		);

		if ( ! is_resource ($sock) )
			$this->setError (sprintf ('%s (%s)', $errstr, $errno));

		$query = $this->querySet ($domain, $server);

		fwrite ($sock, $query. "\r\n");

		while ( ($buf = fgets ($sock, 1024)) ) {
			$recv .= $buf;
			$this->nextServer ($buf);
			if ( $this->debug ) {
				fprintf (STDERR, "%-5s : %s\n", 'SRC', trim ($buf));
				fprintf (STDERR, "%-5s : %s\n", 'PNEXT', $this->pnext);
				fprintf (STDERR, "%-5s : %s\n", 'NEXT', $this->next);
			}
		}

		fclose ($sock);

		if ( ip2long ($domain) && strlen ($this->next) == 2 ) {
			if ( array_search (strtolower ($this->next), $this->allows) === false )
				$this->next = '';
		}

		if ( $this->recurse && $this->next && $this->pnext != $this->next ) {
			if ( ! preg_match ('/\./', $this->next) )
				$this->next = sprintf ('%s.whois-servers.net', $this->next);

			$this->pnext = $this->next;

			$nserver = $this->next;
			$this->next = '';
			$nval = $this->query ($nserver, $domain, $timeout);
			if ( $nval && ! preg_match ('/no match|out of this regist/i', $nval) ) {
				$recv = $nval;
				$server = $nserver;
			}
		}

		return $recv;
	}
	// }}}

	// {{{ +-- public (string) detect (&$v)
	/**
	 * 주어진 도메인의 whois server를 결정
	 *
	 * @access public
	 * @return string
	 * @param string   도메인 이름
	 */
	public function detect (&$v) {
		$v = strtolower ($v);

		if ( ip2long ($v) )
			return 'whois.arin.net';

		if ( ! preg_match ('/\.([a-zA-z]{2,})$/', $v, $m) )
			return 'whois.crsnic.net';
		else
			$ext = $m[1];

		if ( strlen ($ext) == 2 ) {
			if ( preg_match ('/\.co\.nl$/', $v) )
				return 'whois.co.nl';
			else if ( preg_match ('/\.(ac|gov)\.uk$/', $v) )
				return 'whois.ja.net';
			else if ( preg_match ('/\.(cd|dz|so)$/', $v) )
				return sprintf ('whois.nic.%s', $ext);
			else {
				switch ($ext) {
					case 'bj' :
						return 'whois.register.bg';
					case 'bz' :
						return 'whois.belizenic.bz';
					case 'ng' :
						return 'whois.nic.net.ng';
					case 'su' :
						return 'whois.tcinet.ru';
					case 'tc' :
						return 'whois.adamsnames.tc';
					default :
						return sprintf ('%s.whois-servers.net', $ext);
				}
			}
		}

		switch ($ext) {
			case 'asia' :
				return 'whois.nic.asia';
			case 'aero' :
				return 'whois.aero';
			case 'arpa' :
				return 'whois.iana.org';
			case 'biz' :
				return 'whois.nic.biz';
			case 'cat' :
				return 'whois.cat';
			case 'coop' :
				return 'whois.nic.coop';
			case 'gov' :
				return 'whois.nic.gov';
			case 'info' :
				return 'whois.afilias.info';
			case 'int' :
				return 'whois.iana.org';
			case 'jobs' :
				return 'jobswhois.verisign-grs.com';
			case 'mil' :
				return 'whois.nic.mil';
			case 'mobi' :
				return 'whois.dotmobiregistry.net';
			case 'museum' :
				return 'whois.museum';
			case 'name' :
				return 'whois.nic.name';
			case 'org' :
				return 'whois.pir.org';
			case 'pro' :
				return 'whois.nic.pro';
			case 'tel' :
				return 'whois.nic.tel';
			case 'tarvel' :
				return 'whois.nic.travel';
			case 'xxx' :
				return 'whois.nic.xxx';
			default:
				if ( preg_match ('/((br|cn|eu|gb|hu|no|qc|sa|se|uk|us|uy|za)\.com|(gb|se|uk)\.net)$/', $v) )
					return 'whois.centralnic.com';
				else
					return 'whois.crsnic.net';
		}

		return 'whois.crsnic.net';
	}
	// }}}

	// {{{ +-- private nextServer (&$v, &$next)
	private function nextServer (&$v) {
		$v = strtolower ($v);
		if ( ! preg_match ('/(referralserver|whois server|country|country code):/', $v) )
			return false;

		$v = preg_replace ('/^[^:]+:/', '', $v);
		$v = trim (preg_replace ('!(http|whois)://!', '', $v));

		if ( ! $this->next ) {
			$this->next = $v;
			return true;
		}

		if ( $this->next == $v )
			return false;

		if ( preg_match ('/\./', $this->next) )
			return false;
		else
			$this->next = $v;

		return true;
	}
	// }}}

	// {{{ +-- private querySet (&$v, $server)
	private function querySet (&$v, $server) {
		$server = preg_replace ('/:[0-9]+$/', '', $server);

		if ( ip2long ($v) && $server == 'whois.arin.net' )
			return 'n ' . $v;

		if ( preg_match ('/\.jp/', $v) )
			return sprintf ("%s/e\r\n", $v);

		return sprintf ("%s%s\r\n", ($server == 'whois.crsnic.net') ? '=' : '', $v);
	}
	// }}}

	// {{{ +-- private setError (&$msg, $level = E_USER_ERROR)
	private function setError (&$msg, $level = E_USER_ERROR) {
		throw new \myException ($msg, $level);
	}
	// }}}
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
?>
