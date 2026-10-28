<?php
$c = $_GET['c'];
if (preg_match('/flag|cat/i', $c)) {
    die('blocked');
}
system($c);
