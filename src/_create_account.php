<?php
require_once __DIR__."/vendor/autoload.php";
use BitForward\bitForward;

$bf = new BitForward\bitForward();
$bf->createAccount();

unset($bf);
