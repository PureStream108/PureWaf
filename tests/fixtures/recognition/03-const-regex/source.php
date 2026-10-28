<?php
$p = '/flag/i';
$c = $_GET['c'];
if (preg_match($p, $c)) {
    die('blocked');
}
system($c);
