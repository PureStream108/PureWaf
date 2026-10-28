# CHANGELOG

## 2.2.0

（1）增强静态分析能力：

- 引入 SAST 包，和之前启发式分析合并输出结果
- 支持跨函数参数污点、try/catch 路径
- AUTO 新增 engine=heuristic|sast|both
- WebUI 默认 both，CLI/Agent 默认 heuristic

（2）优化 Payload 生成：

- 新增 planner，命令拆成 IR，组合 quote/wildcard/backslash/IFS/concat/base64 算子并按可靠性排序；
- 新增 planner oracle，按成功率重排；
- 新增固定前缀逃逸、/u 非法 UTF-8、数组回调、extract 覆盖、跨超全局、include 强制后缀；
- 修复 eval 缺分号、('phpinfo')() 误判、最短候选不含分隔符等问题；

（3）新增 PHP 本地验证，增加了沙箱，预防恶意命令执行

## 2.1.2

（1）增加了对不同版本 PHP 的适配

（2）增加了Auto模式下锁定 PHP 版本的功能

PS：此版本为1.2.0后最新包版本

## 2.1.1

优化了解题逻辑，补充了文档

## 2.1.0

增加了自定义命令，并可结合LLM与本项目自行生成可以绕过 Waf 的命令

关于 Waf 的判断逻辑：

（1）移除了无用的代码

（2）优化了对 flag 字符的处理逻辑

（3）优化了 auto 检测逻辑

关于 payload 生成：

（1）增加对 base64 的去重

（2）优化异或的时间复杂度

优化了 Agent 运行的逻辑和 LLM 的调用逻辑

优化了 Payload 生成的准确性

## 2.0.0

主要增加了 Agent 功能，支持配合 LLM 进行识别与 payload 生成操作，可覆盖更多场景