#!/usr/bin/env python3
"""Extract the 27 <pre> code blocks from the v1.1 HTML into a directory.

src/ and detection/ were produced with this script — it de-tags the syntax-highlighting spans
and unescapes entities, so the C/shell lands byte-for-byte as printed. Re-run to
confirm src/ still matches the document:

    ./extract-blocks.py ./Adv_Linux_Threat_Detection_*v1.2.html /tmp/blocks
    diff /tmp/blocks/block_10.txt src/memfd_exec.c
"""
import html
import re
import sys
from pathlib import Path

# block index -> filename in src/ (blocks not listed are prose/output/rules)
MAPPING = {
    # -> src/
    8: "hello.c", 9: "sleeper.c", 10: "memfd_exec.c", 11: "memfd_execveat.c",
    12: "memfd_script.c", 13: "interp_oneliner.sh", 14: "tmpfile_exec.c",
    15: "deleted_exec.c", 16: "Makefile", 25: "fileless-gate-preflight.sh",
    # -> gate/ (fragment: does not compile standalone, see gate/README.md)
    19: "exec_gate.bpf.c.fragment",
    # -> detection/
    21: "audit-fileless.rules",
    22: "sigma_fileless_memfd_exec.yml",
    23: "sigma_deleted_binary_exec.yml",
    24: "sigma_payload_piped_to_interpreter.yml",
}


def main(src_html: str, out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    text = Path(src_html).read_text(encoding="utf-8", errors="replace")

    for i, block in enumerate(re.findall(r"<pre[^>]*>(.*?)</pre>", text, re.S)):
        code = block.replace("<br>", "\n")
        code = re.sub(r"<[^>]+>", "", code)
        code = html.unescape(code)
        (out / f"block_{i:02d}.txt").write_text(code)
        first = next((l for l in code.split("\n") if l.strip()), "")
        print(f"{i:3d}  {len(code):6d}  {MAPPING.get(i, ''):<28}  {first[:60]}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
