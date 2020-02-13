<?php
namespace BitForward;

//require_once __DIR__."/vendor/autoload.php";

use Elliptic\EC;
use Elliptic\EC\Signature;
use StephenHill\Base58;
use BN\BN;

class bitForward {
	private $privateKey;
	private $curlOpt;
	private $ap = "\x4B\xE0\x00"; // "\x05"
	function __construct($options = null) {
		$this->ec = new EC('secp256k1');
		$this->b58 = new Base58();
		if ( isset($options['private']) ) $this->keyFromPrivate($options['private']);
		if ( isset($options['curl']) ) $this->curlOpt = $options['curl'];
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
			if ( !$this->privateKey ) throw new \Exception("Private key missing");
			$pubkey = $this->privateKey->getPublic(true);
			$pubKeyHex = $pubkey->encode("hex", true);
		}
		$pubhash = $this->hash160(hex2bin($pubKeyHex));
		echo "public       : ".$this->b58->encode("\x00".$pubhash.$this->checkSum("\x00".$pubhash))."\n";
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
			if ( !$this->privateKey ) throw new \Exception("Private key missing");
			$pubkey = $this->privateKey->getPublic(true);
			$pubKeyHex = $pubkey->encode("hex", true);
		}
		$pubhash = $this->hash160(hex2bin($pubKeyHex));//*$pubenc*/);
		//$pubkey = $this->privateKey->getPublic(true);
		//$pubenc = hex2bin($pubkey->encode("hex", true));
		//echo "public       : ".$this->b58->encode("\x00".$pubhash.$this->checkSum("\x00".$pubhash))."\n";

		$script = "\x00"."\x14".$pubhash;
		$scripHash = $this->hash160($script);
		$checksum = $this->checkSum($this->ap.$scripHash);
		//$address = $this->b58->encode("\x4B".$scripHash.$checksum);
		$address = $this->b58->encode($this->ap.$scripHash.$checksum);
		//echo "address      : {$address}\n";
		return $address;
	}
	public function sign($str) {
		if ( !$this->privateKey ) throw new \Exception("Private key missing");
		$hash = $this->hash256($str);
		$signature = $this->privateKey->sign(bin2hex($hash), ["k" => function ($iter) { 
			return new BN(gmp_strval(gmp_random(256), '10'));
		}]);
		$r = $signature->r->toString('hex');
		$s = $signature->s->toString('hex');
		return $this->b58->encode(hex2bin(bin2hex($signature->recoveryParam).$r.$s));
	}
	public function getPrivateHex() {
		$key = $this->privateKey->getPrivate();
		return $key->toString("hex");
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
	public function __call($method, $params) {
		if ( !$this->privateKey ) throw new \Exception("Private key missing");

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

		$msg = json_encode($params[0]);
		$this->errorMessage = "";
		$this->errorCode    = 0;

		$headers = ["api-key: {$address}"];
		$url = "https://xb0ct.com/api/bf/v1/BTC/{$method}/";
		$ch  = curl_init($url);
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
		echo "RECV: {$recv}\n";
		$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		if ( $code != 200 ) {
			$this->errorMessage = $recv;
			$this->errorCode    = $code;
			return false;
		}
		$recv = json_decode($recv, true);
		var_dump($recv);
		if ($recv && isset($recv['sign']) ) $sign = $recv['sign'];
		if ($recv && isset($recv['data']) ) $msg = json_decode($recv['data'], true);
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
}
