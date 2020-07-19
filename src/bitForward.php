<?php
namespace BitForward;

use Elliptic\EC;
use Elliptic\EC\Signature;
use StephenHill\Base58;
use BN\BN;

const csbitForward_curList = ['BTC', 'tBTC'];
const csbitForward_error_Key = "Private key missing";

class bitForward {
	private $privateKey;
	private $curlOpt;
	public $ap = "\x4B\xE0\x00"; // "\xA4\x0D\xD0"; PB1 "\x05" 
	private $public;
	function __construct($options = null) {
		$this->ec = new EC('secp256k1');
		$this->b58 = new Base58();
		$this->curlOpt = [];
		$this->public = "";
		$this->cur = "BTC";
		$this->url = 'https://www.paybit.pro';
		$this->httpDebug = false;
		if ( isset($options['private']) ) $this->keyFromPrivate($options['private']);
		if ( isset($options['curl']) ) $this->curlOpt = $options['curl'];
		if ( isset($options['ap']) ) $this->ap = $options['ap'];
		if ( isset($options['public']) ) $this->public = $options['public'];
		if ( isset($options['cur']) ) $this->cur = $options['cur'];
		if ( isset($options['url']) ) $this->url = $options['url'];
		if ( isset($options['httpDebug']) ) $this->httpDebug = $options['httpDebug'];
		if ( !in_array($this->cur, csbitForward_curList) ) throw new \Exception("Unknown currency");
	}
	public function hash256($msg) {
		return hash('sha256', hash('sha256', $msg, true), true);
	}
	public function checkSum($msg) {
		return substr( hash('sha256', hash('sha256', $msg, true), true), 0, 4); 
	}
	public function hash160($msg) {
		return hash('ripemd160', hash('sha256', $msg, true), true);
	}
	public function genPrivateKey() {
		$this->privateKey = $this->ec->genKeyPair();
	}
	public function keyFromPrivate($str) {
		$this->privateKey = $this->ec->keyFromPrivate($str);
	}
	public function public($pubKeyHex = null) {
		if ( $pubKeyHex === null ) {
			if ( !$this->privateKey ) throw new \Exception(csbitForward_error_Key);
			$pubkey = $this->privateKey->getPublic(true);
			$pubKeyHex = $pubkey->encode("hex", true);
		}
		//var_dump($pubKeyHex);
		$pubhash = $this->hash160(hex2bin($pubKeyHex));
		//echo "public       : ".$this->b58->encode("\x00".$pubhash.$this->checkSum("\x00".$pubhash))."\n";
		return $this->b58->encode("\x00".$pubhash.$this->checkSum("\x00".$pubhash));
	}
	public function address($pubKeyHex = null) {
		/*
		$script = "\x00"."\x14".$pubhash;
		$scripHash = hash('ripemd160', hash('sha256', $script, true), true);
		$checksum = substr( hash('sha256', hash('sha256', TestNet . $scripHash, true), true), 0, 4); 
		echo "Address      : ".$b58->encode(TestNet . $scripHash . $checksum)."\n";
		*/
		if ( $pubKeyHex === null ) {
			if ( !$this->privateKey ) throw new \Exception(csbitForward_error_Key);
			$pubkey = $this->privateKey->getPublic(true);
			$pubKeyHex = $pubkey->encode("hex", true);
		}
		$pubhash = $this->hash160(hex2bin($pubKeyHex));//*$pubenc*/);
		//$pubkey = $this->privateKey->getPublic(true);
		//$pubenc = hex2bin($pubkey->encode("hex", true));
		//echo "public       : ".$this->b58->encode("\x00".$pubhash.$this->checkSum("\x00".$pubhash))."\n";

		$script = "\x00"."\x14".$pubhash;
		$scriptHash = $this->hash160($script);
		$checksum = $this->checkSum($this->ap.$scriptHash);
		//$address = $this->b58->encode("\x4B".$scripHash.$checksum);
		$address = $this->b58->encode($this->ap.$scriptHash.$checksum);
		//echo "address      : {$address}\n";
		return $address;
	}
	public function sign($str) {
		if ( !$this->privateKey ) throw new \Exception(csbitForward_error_Key);
		$hash = $this->hash256($str);
		$signature = $this->privateKey->sign(bin2hex($hash), ["k" => function ($iter) { 
			return new BN(gmp_strval(gmp_random_bits(250), '10'));
		}]);
		/*
		$signature = $this->privateKey->sign(bin2hex($hash), ["k" => function ($iter) { 
			return new BN('162897322');
		}]);
		*/

		$r = $signature->r->toString('hex');
		$s = $signature->s->toString('hex');
		//var_dump($r, $s, bin2hex($signature->recoveryParam));
		return $this->b58->encode(hex2bin(bin2hex($signature->recoveryParam).$r.$s));
	}
	public function getPrivateHex() {
		$key = $this->privateKey->getPrivate();
		return $key->toString("hex");
	}
	public function getPublicHex() {
		$key = $this->privateKey->getPublic(true);
		return $key->encode("hex", true);
	}
	public function keyFromSignature($msg, $signature) {
		$signbin = $this->b58->decode($signature);
		$hash = bin2hex($this->hash256($msg));
		$signarr = [
			"r" => bin2hex(substr($signbin,  1, 32)),
			"s" => bin2hex(substr($signbin, 33, 32)) 
		];
		$nv = ord(substr($signbin, 0, 1)) - ord('0');
		$pubkey = $this->ec->recoverPubKey($hash, $signarr, $nv);
		return $pubkey;
	}
	public function addressFromSignature($msg, $signature) {
		$pubkey = $this->keyFromSignature($msg, $signature);
		$address = $this->address( $pubkey->encode("hex", true) );
		return $address;
	}
	public function wif() {
		if ( !$this->privateKey ) throw new \Exception(csbitForward_error_Key);
		$hex = hex2bin("80".$this->getPrivateHex()."01");
		$checksum = $this->checksum($hex);
		$hex = $hex.$checksum;
		return $this->b58->encode($hex);
	}
	public function __call($method, $params) {
		if ( !$this->privateKey ) throw new \Exception(csbitForward_error_Key);

		/*
		$pubkey = $this->privateKey->getPublic(true);
		$pubenc = hex2bin($pubkey->encode("hex", true));
		$pubhash = $this->hash160($pubenc);
		//echo "public       : ".$this->b58->encode("\x00".$pubhash.$this->checkSum($pubhash))."\n";

		$script = "\x00"."\x14".$pubhash;
		$scripHash = $this->hash160($script);
		$checksum = $this->checkSum($scripHash);
		$address = $this->b58->encode("\x05".$scripHash.$checksum);

		//echo "redeemScript : ".bin2hex($script)." [".strlen($script)."]\n";
		
		$script = "\xA9"."\x14".$scripHash."\x87";
		//echo "scriptPubKey : ".bin2hex($script)." [".strlen($script)."]\n";
		//echo "address      : {$address}\n";
		*/
		$pubkey = $this->privateKey->getPublic(true);
		$address = $this->address( $pubkey->encode("hex", true) );
		$msg = ( isset($params[0]) ? $params[0] : [] );
		$msg = json_encode($msg);
		//var_dump($msg);
		//var_dump($params);
		$this->errorMessage = "";
		$this->errorCode    = 0;

		$headers = ["api-key: {$address}"];
		$method = str_replace("_", "/", $method);
		$url = "{$this->url}/api/bf/v1/{$this->cur}/{$method}/";
		$ch  = curl_init($url);
		curl_setopt($ch, CURLOPT_VERBOSE, $this->httpDebug);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, [
			'data' => $msg,
			'sign' => $this->sign($msg)
		]);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
		foreach ($this->curlOpt as $k => $v) {
			curl_setopt($ch, $k, $v);
		}

		//$this->pm->start('curl_exec');
		$recv = curl_exec($ch);
		if ( $this->httpDebug ) echo "RECV: {$recv}\n";
		$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		if ( $code != 200 ) {
			$this->errorMessage = $recv;
			$this->errorCode    = $code;
			return false;
		}
		$recv = json_decode($recv, true);
		$msg = null;
		$sign = null;
		if ($recv && isset($recv['sign']) ) $sign = $recv['sign'];
		if ($recv && isset($recv['data']) ) $msg = json_decode($recv['data'], true);
		if ( !$msg || !$sign ) return false;
		if ($msg && isset($msg['error']) && $msg['error']) {
			$this->errorMessage = $msg['data'];
			$this->errorCode    = -1;
			return false;
		}
		$signer = $this->addressFromSignature(json_encode($msg), $sign);
		$msg['sign'] = $sign;
		$msg['signer'] = $signer;
		return $msg;
	}
	public function signCheck($recv, $pub = "") {
		//$recv = json_decode($recv, true);
		if ( !is_array($recv) ) return false;
		if ( !isset($recv['data']) ) return false;
		if ( !isset($recv['sign']) ) return false;
		$msg   = $recv['data'];
		$sign  = $recv['sign'];
		try {
			$signAddress = $this->addressFromSignature($msg, $sign);
		} catch (Exception $e) {
			$signAddress = "ERROR";
		}
		$pub = ( $pub ? $pub : $this->public );

		if ( $pub && $signAddress !== $pub ) return false;
		$msg = json_decode($msg, true);
		$signer = $this->addressFromSignature(json_encode($msg), $sign);
		$msg['sign'] = $sign;
		$msg['signer'] = $signer;
		return $msg;
	}
	public function createAccount($saveFile = true) {
		$this->genPrivateKey();
		$res = $this->ping();
		$private = $this->getPrivateHex();
		$public  = $res['signer'];
		$out = 
"<?php
require_once __DIR__.\"/vendor/autoload.php\";
use BitForward\bitForward;

\$bf = new bitForward([
  'cur'     => 'tBTC',
  'private' => '{$private}',
  'public'  => '{$public}'
]);";
		$ping = $out."
\$res = \$bf->ping();
echo ( \$res && \$res['signer'] == '{$public}' ? \"succes\\n\" : \"error\\n\" );
";
		$sign = $out.'
$hash = getenv( strtoupper("HASH") );
echo "ADDR: {$bf->address()}\n";
echo "HASH: {$hash}\n";
echo "SIGN: {$bf->sign($hash)}\n";
';
		echo $ping;
		if ( $saveFile ) {
			$handle = fopen('bf_ping.php', 'w');
			try {
				fwrite($handle, $ping);
			} finally {
				fclose($handle);
			}
		}
		if ( $saveFile ) {
			$handle = fopen('bf_sign.php', 'w');
			try {
				fwrite($handle, $sign);
			} finally {
				fclose($handle);
			}
		}
	}
}
