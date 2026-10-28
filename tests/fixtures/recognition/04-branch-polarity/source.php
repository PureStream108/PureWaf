<?php
$c = $_GET['c'];
if (str_contains($c, 'cat')) {
    echo 'blocked';
} else {
    system($c);
}
