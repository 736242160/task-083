"""流式块引用即时校验器（纯 Python 标准库，单文件）。

块文本逐块流入：每块含 名称、声明列表、引用列表，块可嵌套。
能力：
  1. 声明随块流入即时登记，引用即时校验；
  2. 前向引用（尚未声明）先挂起，后续块/后续片段补声明后自动完成；
  3. 块关闭时仍未完成的引用按引用位置报告；
  4. 块关闭时未闭合的嵌套块报告；
  5. 声明遮蔽随块作用域生效，引用绑定到最近的可见声明；
  6. 引用环（a 引用 b、b 引用 a）在环闭合时报告环上名称；
  7. 块名称重复报告；
  8. 输出校验过程日志与最终错误清单。

直接运行 `python3 stream_validator.py` 可看到覆盖全部特性的示例。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Scope:
    """一个块对应一个作用域。"""
    block: str
    sid: int
    parent: Optional["Scope"]
    decls: dict = field(default_factory=dict)  # 名称 -> 登记位置


@dataclass
class PendingRef:
    """挂起的前向引用。chain 为引用发生时自内而外的可见作用域链。"""
    name: str
    pos: str
    chain: tuple
    block: str


class StreamValidator:
    def __init__(self):
        self._seq = 0
        self._sid = 0
        self.scopes = []          # 作用域栈，栈底为最外层块
        self.block_names = {}     # 块名 -> 首次开启位置（查重）
        self.pending = []         # 挂起引用列表
        self.graph = {}           # 依赖图：块名 -> 被引用名称集合
        self._cycles_seen = set() # 已报告过的环（按节点集合去重）
        self.logs = []            # 校验过程
        self.errors = []          # 错误清单：(类别, 描述)

    # ---------- 基础设施 ----------
    def _next_pos(self):
        self._seq += 1
        return f"事件#{self._seq}"

    def _log(self, msg):
        self.logs.append(msg)
        print(f"[校验] {msg}")

    def _error(self, kind, msg):
        self.errors.append((kind, msg))
        print(f"[错误] {kind}: {msg}")

    @property
    def _cur(self):
        return self.scopes[-1] if self.scopes else None

    def _lookup(self, name, start=None):
        """自内而外查找最近可见声明（遮蔽语义）。"""
        sc = start if start is not None else self._cur
        while sc is not None:
            if name in sc.decls:
                return sc
            sc = sc.parent
        return None

    # ---------- 流入接口 ----------
    def begin_block(self, name, declares=(), refs=()):
        """块流入：登记块名、开作用域，顺序处理声明与引用。
        declares/refs 元素为名称字符串，或 (名称, 位置) 元组。"""
        pos = self._next_pos()
        if name in self.block_names:
            self._error("DUPLICATE_BLOCK",
                        f"块名称重复: {name}（首次开启于 {self.block_names[name]}，再次于 {pos}）")
        else:
            self.block_names[name] = pos
        self._sid += 1
        self.scopes.append(Scope(name, self._sid, self._cur))
        self._log(f"开启块 {name} @ {pos}")
        for d in declares:
            self.declare(*(d if isinstance(d, tuple) else (d,)))
        for r in refs:
            self.reference(*(r if isinstance(r, tuple) else (r,)))

    def declare(self, name, pos=None):
        """声明流入：即时登记，并唤醒可见链上的挂起引用。"""
        pos = pos or self._next_pos()
        cur = self._cur
        if cur is None:
            self._error("NO_BLOCK", f"声明 {name} @ {pos} 出现在任何块之外")
            return
        outer = self._lookup(name, start=cur.parent)
        cur.decls[name] = pos
        if outer is not None:
            self._log(f"登记声明 {name} @ {pos}（块 {cur.block}，遮蔽外层块 {outer.block} 的同名声明）")
        else:
            self._log(f"登记声明 {name} @ {pos}（块 {cur.block}）")
        for ref in list(self.pending):
            if ref.name != name:
                continue
            # 引用处于挂起态，说明其可见链上此前无此声明；
            # 当前作用域在链上即成为最近可见声明，完成绑定。
            if any(sc is cur for sc in ref.chain):
                self.pending.remove(ref)
                self._log(f"前向引用 {name}（引用位置 {ref.pos}）由 {pos} 的声明补全，"
                          f"绑定到块 {cur.block}")

    def reference(self, name, pos=None):
        """引用流入：记录依赖边并检环，能解析即通过，否则挂起。"""
        pos = pos or self._next_pos()
        cur = self._cur
        if cur is None:
            self._error("NO_BLOCK", f"引用 {name} @ {pos} 出现在任何块之外")
            return
        self._add_edge(cur.block, name, pos)
        target = self._lookup(name)
        if target is not None:
            self._log(f"引用 {name} @ {pos} 即时通过，绑定到块 {target.block} "
                      f"中 {target.decls[name]} 处的声明")
        else:
            chain = []
            sc = cur
            while sc is not None:
                chain.append(sc)
                sc = sc.parent
            self.pending.append(PendingRef(name, pos, tuple(chain), cur.block))
            self._log(f"引用 {name} @ {pos} 尚未声明，挂起等待后续块补充")

    def end_block(self, name, pos=None):
        """块关闭：弹出作用域；报告块内仍未完成的引用与未闭合嵌套。"""
        pos = pos or self._next_pos()
        if not self.scopes:
            self._error("UNMATCHED_CLOSE", f"关闭块 {name} @ {pos}，但当前没有打开的块")
            return
        if self._cur.block == name:
            self._pop_scope(pos)
            return
        names = [s.block for s in self.scopes]
        if name in names:
            idx = len(names) - 1 - names[::-1].index(name)
            unclosed = [s.block for s in self.scopes[idx + 1:]]
            self._error("UNCLOSED_BLOCK",
                        f"关闭块 {name} @ {pos} 时，内层嵌套块未闭合: {unclosed}")
            while len(self.scopes) > idx:
                self._pop_scope(pos)
        else:
            self._error("UNMATCHED_CLOSE",
                        f"关闭块 {name} @ {pos}，与当前打开块 {self._cur.block} 不匹配")

    def finish(self):
        """输入结束：报告所有仍未闭合的块，返回错误清单。"""
        pos = self._next_pos()
        while self.scopes:
            self._error("UNCLOSED_BLOCK", f"输入结束 @ {pos}：块 {self._cur.block} 仍未闭合")
            self._pop_scope(pos)
        return self.errors

    # ---------- 内部 ----------
    def _pop_scope(self, pos):
        scope = self.scopes.pop()
        for ref in list(self.pending):
            if ref.chain and ref.chain[0] is scope:
                self.pending.remove(ref)
                self._error("UNRESOLVED_REF",
                            f"块 {scope.block} 关闭 @ {pos}：引用 {ref.name} 始终未声明"
                            f"（引用位置 {ref.pos}）")
        self._log(f"关闭块 {scope.block} @ {pos}")

    def _add_edge(self, src, dst, pos):
        self.graph.setdefault(src, set()).add(dst)
        path = self._find_path(dst, src)
        if path is not None:
            cyc = [src] + path  # src -> dst -> ... -> src（path 末节点即 src）
            key = frozenset(cyc)
            if key not in self._cycles_seen:
                self._cycles_seen.add(key)
                self._error("CYCLE",
                            f"检测到引用环 @ {pos}: " + " -> ".join(cyc))

    def _find_path(self, start, goal):
        """在依赖图中找 start 到 goal 的一条路径，返回节点列表。"""
        stack = [(start, [start])]
        seen = {start}
        while stack:
            node, path = stack.pop()
            if node == goal:
                return path
            for nxt in self.graph.get(node, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append((nxt, path + [nxt]))
        return None

    # ---------- 输出 ----------
    def report(self):
        lines = ["==== 错误清单 ===="]
        if not self.errors:
            lines.append("（无错误）")
        for i, (kind, msg) in enumerate(self.errors, 1):
            lines.append(f"{i}. [{kind}] {msg}")
        return "\n".join(lines)


if __name__ == "__main__":
    v = StreamValidator()

    print("---- 1) 声明即时登记、引用即时校验 ----")
    v.begin_block("main", declares=["x"], refs=["x"])

    print("---- 2) 前向引用：先挂起，后续片段补声明后自动完成 ----")
    v.reference("later")
    v.declare("later")

    print("---- 3) 遮蔽：内层同名声明遮蔽外层，引用绑定内层 ----")
    v.begin_block("inner", declares=["x"], refs=["x"])

    print("---- 4) 无法完成的引用：块关闭时按引用位置报告 ----")
    v.reference("missing")
    v.end_block("inner")

    print("---- 5) 引用环：mod_a 引用 mod_b、mod_b 引用 mod_a，环闭合即报告 ----")
    v.declare("mod_a")
    v.declare("mod_b")
    v.begin_block("mod_a", refs=["mod_b"])
    v.begin_block("mod_b", refs=["mod_a"])
    v.end_block("mod_b")
    v.end_block("mod_a")

    print("---- 6) 块名称重复 ----")
    v.begin_block("mod_a")
    v.end_block("mod_a")

    print("---- 7) 块关闭时内层嵌套未闭合 ----")
    v.begin_block("outer")
    v.begin_block("leaky")
    v.end_block("outer")

    print("---- 8) 输入结束仍有块未闭合 ----")
    v.begin_block("forgotten")
    v.finish()

    print()
    print(v.report())
