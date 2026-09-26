#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流式块引用即时校验器（纯 Python 标准库，单文件）。

输入协议（逐行文本，可按任意字节边界分块流入）：
    block <名称>     开启一个块（可嵌套）
    decl <名称>      在当前块登记一个声明（即时生效）
    ref  <名称>      在当前块发起一个引用（即时校验）
    end  [名称]      关闭当前块；带名称时校验匹配，若不匹配则
                     将其上未闭合的嵌套块报告后一并关闭
    # 注释 / 空行    忽略（支持行内注释）

校验语义：
  * 声明即时登记，引用即时校验；引用按作用域链（当前块 -> 外层块）查找，
    内层同名声明遮蔽外层，绑定到最近可见声明。
  * 引用尚未声明（前向引用）时挂起；之后每登记一个声明，所有可见该声明的
    挂起引用自动完成校验并绑定。
  * 块关闭时，该块内仍未完成的引用按引用位置（行号）报告。
  * 块关闭（或输入结束）时仍未闭合的嵌套块被报告。
  * 引用归属：一个引用挂在它所在块中最近的前置声明上（块内尚无声明时挂在
    块自身），据此构建依赖图；新增依赖边使图成环时，报告环上的名称。
  * 块名称重复（全局）要报告。

输出：完整校验过程日志 + 末尾错误清单。

用法：
    python3 stream_block_validator.py            # 运行内置演示（分块流入）
    python3 stream_block_validator.py 输入文件    # 校验外部文件
"""

from __future__ import annotations

import sys
from collections import deque


# ---------------------------------------------------------------- 数据模型

class Scope:
    """一个块对应的作用域。"""
    __slots__ = ("name", "parent", "line", "decls", "last_decl")

    def __init__(self, name, parent, line):
        self.name = name
        self.parent = parent
        self.line = line          # 块开启所在行
        self.decls = {}           # 名称 -> Decl（本块内）
        self.last_decl = None     # 本块最近一个声明（引用归属上下文）


class Decl:
    __slots__ = ("name", "scope", "line")

    def __init__(self, name, scope, line):
        self.name = name
        self.scope = scope
        self.line = line


class Ref:
    __slots__ = ("name", "scope", "line", "owner")

    def __init__(self, name, scope, line, owner):
        self.name = name
        self.scope = scope        # 引用所在作用域（决定可见性）
        self.line = line          # 引用位置（报告用）
        self.owner = owner        # 依赖边起点：所属声明名或 <block:块名>


# ---------------------------------------------------------------- 校验器

class StreamValidator:
    """流式校验器：feed() 逐块喂入文本，close() 结束输入。"""

    def __init__(self):
        self.root = Scope("<global>", None, 0)
        self.scopes = [self.root]          # 作用域栈，栈底为全局作用域
        self.pending = []                  # 挂起的引用（Ref）
        self.edges = {}                    # 依赖图：节点 -> 后继节点集合
        self.errors = []                   # (kind, line, message)
        self.log_lines = []                # 校验过程日志
        self.block_names = {}              # 块名 -> 首次开启行号（查重）
        self.reported_cycles = set()       # 已报告过的环（按节点集合去重）
        self._buf = ""
        self.lineno = 0
        self._closed = False

    # ---------------- 流式输入 ----------------

    def feed(self, text):
        """喂入一段文本（可跨行、可不足一行）。"""
        if self._closed:
            raise RuntimeError("校验器已关闭，不能再 feed")
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self.lineno += 1
            self._process_line(line)

    def close(self):
        """输入结束：处理残余行，报告未闭合块与未完成引用。"""
        if self._closed:
            return
        if self._buf.strip():
            self.lineno += 1
            self._process_line(self._buf)
        self._buf = ""
        while len(self.scopes) > 1:
            scope = self.scopes[-1]
            self._error("UNCLOSED_BLOCK", self.lineno,
                        f"块 '{scope.name}'（行 {scope.line} 开启）在输入结束时仍未闭合")
            self._close_scope(scope, reason="输入结束")
        self._closed = True
        self._log(self.lineno, "输入结束，校验完成")

    # ---------------- 行解析 ----------------

    def _process_line(self, raw):
        line = raw.split("#", 1)[0].strip()
        if not line:
            return
        parts = line.split()
        cmd, args = parts[0], parts[1:]
        if cmd == "block" and len(args) == 1:
            self._cmd_block(args[0])
        elif cmd == "decl" and len(args) == 1:
            self._cmd_decl(args[0])
        elif cmd == "ref" and len(args) == 1:
            self._cmd_ref(args[0])
        elif cmd == "end" and len(args) <= 1:
            self._cmd_end(args[0] if args else None)
        else:
            self._error("PARSE", self.lineno, f"无法解析的指令: {raw.strip()!r}")

    # ---------------- 指令处理 ----------------

    def _cmd_block(self, name):
        if name in self.block_names:
            self._error("DUPLICATE_BLOCK", self.lineno,
                        f"块名称 '{name}' 重复（首次出现于行 {self.block_names[name]}）")
        else:
            self.block_names[name] = self.lineno
        scope = Scope(name, self.scopes[-1], self.lineno)
        self.scopes.append(scope)
        self._log(self.lineno, f"开启块 '{name}'（深度 {len(self.scopes) - 1}）")

    def _cmd_decl(self, name):
        scope = self.scopes[-1]
        if name in scope.decls:
            self._log(self.lineno, f"声明 '{name}' 在块 '{scope.name}' 内重复登记，后者覆盖前者")
        decl = Decl(name, scope, self.lineno)
        scope.decls[name] = decl
        scope.last_decl = decl
        self._log(self.lineno, f"登记声明 '{name}' -> 块 '{scope.name}'")
        # 新声明可能完成若干挂起引用（仅同名引用可能因此变为可见）
        for ref in list(self.pending):
            if ref.name != name:
                continue
            target = self._lookup(ref.name, ref.scope)
            if target is not None:
                self._resolve(ref, target, via="挂起后自动完成")

    def _cmd_ref(self, name):
        scope = self.scopes[-1]
        owner = scope.last_decl.name if scope.last_decl else f"<block:{scope.name}>"
        ref = Ref(name, scope, self.lineno, owner)
        target = self._lookup(name, scope)
        if target is None:
            self.pending.append(ref)
            self._log(self.lineno, f"引用 '{name}'（归属 {owner}）未找到声明，挂起等待")
        else:
            self._resolve(ref, target, via="即时校验通过")

    def _cmd_end(self, name):
        if len(self.scopes) == 1:
            self._error("UNMATCHED_END", self.lineno, "end 出现时没有已开启的块")
            return
        if name is None:
            self._close_scope(self.scopes[-1], reason="正常关闭")
            return
        # 带名关闭：自栈顶向下找最近的同名块
        idx = None
        for i in range(len(self.scopes) - 1, 0, -1):
            if self.scopes[i].name == name:
                idx = i
                break
        if idx is None:
            self._error("UNMATCHED_END", self.lineno,
                        f"end '{name}' 没有匹配的已开启块")
            return
        # 其上的嵌套块均未闭合
        for scope in self.scopes[idx + 1:]:
            self._error("UNCLOSED_BLOCK", self.lineno,
                        f"块 '{scope.name}'（行 {scope.line} 开启）在块 '{name}' 关闭时仍未闭合")
        while len(self.scopes) > idx + 1:
            self._close_scope(self.scopes[-1], reason=f"随块 '{name}' 关闭而被关闭")
        self._close_scope(self.scopes[-1], reason="正常关闭")

    # ---------------- 核心语义 ----------------

    def _lookup(self, name, scope):
        """沿作用域链查找最近可见声明（内层遮蔽外层）。"""
        while scope is not None:
            decl = scope.decls.get(name)
            if decl is not None:
                return decl
            scope = scope.parent
        return None

    def _resolve(self, ref, target, via):
        if ref in self.pending:
            self.pending.remove(ref)
        self._log(ref.line,
                  f"引用 '{ref.name}'（归属 {ref.owner}）{via}，"
                  f"绑定到块 '{target.scope.name}' 的声明（行 {target.line}）")
        self._add_edge(ref.owner, ref.name, ref.line)

    def _add_edge(self, src, dst, line):
        """加入依赖边 src -> dst；若因此成环，报告环上名称。"""
        path = self._find_path(dst, src)
        if path is not None:
            cycle = [src] + path          # src -> dst -> ... -> src
            key = frozenset(cycle)
            if key not in self.reported_cycles:
                self.reported_cycles.add(key)
                self._error("CYCLE", line,
                            f"引用环闭合: {' -> '.join(cycle)}（环上名称: "
                            f"{', '.join(sorted(key))}）")
        self.edges.setdefault(src, set()).add(dst)

    def _find_path(self, start, goal):
        """BFS 求 start 到 goal 的一条路径（含两端），不存在返回 None。"""
        if start == goal:
            return [start]
        visited = {start}
        queue = deque([(start, [start])])
        while queue:
            node, path = queue.popleft()
            for nxt in self.edges.get(node, ()):
                if nxt == goal:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))
        return None

    def _close_scope(self, scope, reason):
        """关闭作用域：弹出栈，报告该块内仍未完成的挂起引用。"""
        for ref in list(self.pending):
            if ref.scope is scope:
                self.pending.remove(ref)
                self._error("UNRESOLVED_REF", ref.line,
                            f"引用 '{ref.name}'（位于块 '{scope.name}'）"
                            f"在块关闭时仍未完成（无可见声明）")
        self.scopes.remove(scope)
        self._log(self.lineno, f"关闭块 '{scope.name}'（{reason}）")

    # ---------------- 输出 ----------------

    def _log(self, line, msg):
        self.log_lines.append(f"[行 {line:>3}] {msg}")

    def _error(self, kind, line, msg):
        self.errors.append((kind, line, msg))
        self._log(line, f"!! {kind}: {msg}")

    def report(self):
        out = ["===== 校验过程 ====="]
        out.extend(self.log_lines)
        out.append("")
        out.append("===== 错误清单 =====")
        if not self.errors:
            out.append("（无错误，全部校验通过）")
        else:
            for i, (kind, line, msg) in enumerate(self.errors, 1):
                out.append(f"{i:2d}. [{kind}] 行 {line}: {msg}")
            out.append(f"共 {len(self.errors)} 个错误")
        return "\n".join(out)


# ---------------------------------------------------------------- 演示

DEMO = """\
# --- 1. 即时校验：声明先于引用，立即通过 ---
block alpha
decl a
decl b
ref a

# --- 2. 前向引用：先挂起，同块后续声明补登后自动完成 ---
ref c
decl c

# --- 3. 嵌套与遮蔽：内层同名声明遮蔽外层，绑定到内层 ---
block beta
decl a
decl ab
ref a
ref missing
end beta

# --- 4. 挂起引用由后续内容（隔一个嵌套块）补登完成 ---
block gamma
ref d
block helper
end helper
decl d
end gamma

# --- 5. 引用环：x -> y -> x，环闭合时报告环上名称 ---
block loop
decl x
ref y
decl y
ref x
end loop
end alpha

# --- 6. 块名称重复 ---
block alpha
end alpha

# --- 7. 块关闭时存在未闭合的嵌套 ---
block delta
block epsilon
end delta

# --- 8. 输入结束时仍未闭合的块 + 未完成引用 ---
block zeta
ref never
"""


def main(argv):
    if len(argv) > 1:
        with open(argv[1], encoding="utf-8") as f:
            text = f.read()
        print(f"===== 输入文件: {argv[1]} =====")
    else:
        text = DEMO
        print("===== 内置演示输入（带行号） =====")
        for i, line in enumerate(text.splitlines(), 1):
            print(f"{i:>3} | {line}")
    print()

    validator = StreamValidator()
    chunk_size = 13  # 故意按非行边界切分，验证真正的流式处理
    for i in range(0, len(text), chunk_size):
        validator.feed(text[i:i + chunk_size])
    validator.close()

    print(validator.report())
    return 1 if validator.errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
