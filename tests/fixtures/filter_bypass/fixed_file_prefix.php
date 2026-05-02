<?php
$name = $_GET['name'] ?? '';
if (preg_match('/flag|cat/i', $name)) {
    die('blocked');
}
system('file ' . $name);
?>
