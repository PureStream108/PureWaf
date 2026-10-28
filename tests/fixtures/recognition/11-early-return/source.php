<?php
$c = $_GET['c'];
if (!preg_match('/flag/', $c)) {
    return;
}
system($c);
