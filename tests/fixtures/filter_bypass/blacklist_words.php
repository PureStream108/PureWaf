<?php
$cmd = $_POST['cmd'] ?? '';
if (preg_match('/cat|flag/i', $cmd)) {
    die('blocked');
}
system($cmd);
?>
