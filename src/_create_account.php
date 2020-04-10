<?php
require_once __DIR__."/vendor/autoload.php";
use BitForward\bitForward;

function createAccount($saveFile = true) {
	echo "Creating new bitForward account...\n";
	$bf = new BitForward\bitForward();
	echo "Generating new private key...\n";
	$bf->genPrivateKey();
	echo "Sending message to the server...\n";
	$res = $bf->ping();
	if ( $res == false ) die("{$bf->errorCode}: {$bf->errorMessage}\n");
	if ( isset($res['error']) && $res['error'] === true ) die("ERROR: {$bf->errorMessage}\n");
	echo "The operation complete successfully\n";
	$public = $res['signer'];
	$out = 
"<?php
require_once __DIR__.\"/vendor/autoload.php\";
use BitForward\bitForward;

\$bf = new bitForward([
  'private' => '{$private}',
  'public'  => '{$public}'
]);
\$res = \$bf->ping();
echo ( \$res['signer'] == '{$public}' ? \"succes\\n\" : \"error\\n\" );
";
	echo $out;
	if ( $saveFile ) {
		$handle = fopen('_bf_ping.php', 'w');
		try {
			fwrite($handle, $out);
		} finally {
			fclose($handle);
		}
	}
}
