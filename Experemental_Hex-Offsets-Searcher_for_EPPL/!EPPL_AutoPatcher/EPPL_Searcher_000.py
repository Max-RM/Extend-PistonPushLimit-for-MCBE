#!/usr/bin/env python3
import json
import os
import re
import shutil
import sys
from pathlib import Path

# Try to import tkinter for Windows file picker; fall back to CLI prompt
try:
	import tkinter as tk
	from tkinter import filedialog
	tk_available = True
except Exception:
	tk_available = False

# ---------- UTILS ----------
def parse_hex_pattern(pattern_str: str):
	"""Parses a hex pattern string into a list of (mask, value) pairs.
	Supports "?" nibble wildcards and full-byte token "XX" placeholder.
	Returns (pattern, xx_index) where xx_index is the index of the XX byte or None.
	Example: "11 22 XX 3? ?4".
	"""
	tokens = re.split(r"[\s,]+", pattern_str.strip())
	pattern = []
	xx_index = None
	for idx, tok in enumerate(tokens):
		if not tok:
			continue
		upper_tok = tok.upper()
		if upper_tok == "XX":
			# Placeholder byte to be matched from allowed set
			if xx_index is not None:
				raise ValueError("Only one XX is supported in patternB")
			xx_index = len(pattern)
			pattern.append((0x00, 0x00))  # placeholder; mask 0 so it matches anything if not substituted
			continue
		# Normalize to 2 hex chars or wildcard nibble
		if len(upper_tok) == 1:
			upper_tok = '0' + upper_tok
		if len(upper_tok) != 2:
			raise ValueError(f"Invalid token: '{tok}'")
		hi, lo = upper_tok[0], upper_tok[1]
		mask, val = 0, 0
		if hi != '?':
			mask |= 0xF0
			val |= int(hi, 16) << 4
		if lo != '?':
			mask |= 0x0F
			val |= int(lo, 16)
		pattern.append((mask, val))
	return pattern, xx_index


def match_at(data: bytes, pos: int, pattern):
	"""Match pre-parsed pattern (mask,value) at pos. No XX here."""
	if pos < 0 or pos + len(pattern) > len(data):
		return False
	for i, (mask, val) in enumerate(pattern):
		if (data[pos + i] & mask) != val:
			return False
	return True


def format_off(x: int) -> str:
	return f"0x{x:08X}"


# ---------- CONFIG ----------
def read_top_config(cfg_path: Path):
	"""Reads root config.json with x86/x64 sections.
	Expected structure:
	{
	  "x86": {"patternA": "..", "range": "min-max", "patternB": "..", "xxOptions": {"0C": true, "0D": true, "FF": true}},
	  "x64": { ... }
	}
	"""
	try:
		cfg_obj = json.loads(cfg_path.read_text(encoding='utf-8'))
	except Exception as e:
		raise ValueError(f"Failed to read config.json: {e}")
	for arch in ("x86", "x64"):
		if arch not in cfg_obj:
			raise ValueError(f"Missing '{arch}' section in config.json")
		sect = cfg_obj[arch]
		for key in ("patternA", "range", "patternB", "xxOptions"):
			if key not in sect:
				raise ValueError(f"Missing key '{key}' in config.json -> {arch}")
		# Validate range
		m = re.findall(r"\d+", str(sect["range"]))
		if not m:
			raise ValueError(f"Range has no numbers in {arch}")
		# Validate xxOptions
		xx = sect["xxOptions"]
		for opt in ("0C", "0D", "FF"):
			if opt not in xx or not isinstance(xx[opt], bool):
				raise ValueError(f"xxOptions must have boolean '{opt}' in {arch}")
	return cfg_obj


# ---------- PE ARCH DETECTION ----------
def detect_pe_arch(exe_path: Path) -> str:
	"""Returns 'x86' or 'x64' by reading PE headers.
	Raises ValueError if not a valid PE executable.
	"""
	with exe_path.open('rb') as f:
		data = f.read(0x1000)
	if len(data) < 0x40:
		raise ValueError("File too small to be a valid PE")
	if data[:2] != b'MZ':
		raise ValueError("Not an MZ executable")
	e_lfanew = int.from_bytes(data[0x3C:0x40], 'little')
	with exe_path.open('rb') as f:
		f.seek(e_lfanew)
		sig = f.read(4)
		if sig != b'PE\x00\x00':
			raise ValueError("Invalid PE signature")
		machine = int.from_bytes(f.read(2), 'little')
	if machine == 0x014C:
		return 'x86'
	elif machine == 0x8664:
		return 'x64'
	else:
		raise ValueError(f"Unsupported PE machine: 0x{machine:04X}")


# ---------- SEARCH ----------
def search_xx_offsets(file_path: Path, patternA_str: str, gap_range_str: str, patternB_str: str, allowed_xx_vals):
	"""Search for patternA, then patternB within [min,max] gap.
	patternB may contain one 'XX' placeholder. For each allowed XX value, try to match; if matched, record the absolute offset of the XX byte and the actual matched value.
	Returns (results, filesize) where results is list of tuples (xx_offset, xx_value_hex_str).
	"""
	data = file_path.read_bytes()
	n = len(data)

	patA, xxA = parse_hex_pattern(patternA_str)
	if xxA is not None:
		raise ValueError("patternA must not contain XX")
	patB, xxB = parse_hex_pattern(patternB_str)
	if xxB is None:
		raise ValueError("patternB must contain XX")

	m = re.findall(r"\d+", gap_range_str)
	if not m:
		raise ValueError("Range has no numbers")
	min_gap, max_gap = (int(m[0]), int(m[0])) if len(m) == 1 else (min(int(m[0]), int(m[1])), max(int(m[0]), int(m[1])))

	lenA, lenB = len(patA), len(patB)
	results = []
	pos = 0
	allowed_vals = []
	for key, val in (('0C', 0x0C), ('0D', 0x0D), ('FF', 0xFF)):
		if allowed_xx_vals.get(key):
			allowed_vals.append((key, val))
	if not allowed_vals:
		raise ValueError("No XX options enabled in config")

	while pos + lenA <= n:
		if match_at(data, pos, patA):
			base = pos + lenA
			for gap in range(min_gap, max_gap + 1):
				j = base + gap
				if j + lenB > n:
					continue
				# Try each allowed XX substitution
				for key, val in allowed_vals:
					ok = True
					for i, (mask, mval) in enumerate(patB):
						byte = data[j + i]
						if i == xxB:
							# This position must equal the chosen val exactly
							if byte != val:
								ok = False
								break
						else:
							if (byte & mask) != mval:
								ok = False
								break
					if ok:
						xx_abs = j + xxB
						results.append((xx_abs, key))
			pos += 1
		else:
			pos += 1
	return results, n


# ---------- AM COPY AND CONFIG UPDATE ----------
def copy_am_assets(project_root: Path, arch: str, target_dir: Path):
	"""Copy AM/<arch> contents into target_dir."""
	src_dir = project_root / 'AM' / arch
	if not src_dir.exists():
		raise FileNotFoundError(f"AM/{arch} not found at {src_dir}")
	for item in src_dir.iterdir():
		dest = target_dir / item.name
		if item.is_dir():
			# Merge copy directory
			if dest.exists():
				shutil.rmtree(dest)
			shutil.copytree(item, dest)
		else:
			shutil.copy2(item, dest)
	return target_dir


def write_am_config(dest_dir: Path, exe_name: str, first_off: int, first_xx: str, second_off: int, second_xx: str):
	"""Rewrite AM config.json in dest_dir to required structure."""
	am_cfg = dest_dir / 'config.json'
	patches = [
		f"{format_off(first_off)} >> {first_xx} >> FF",
		f"{format_off(second_off)} >> {second_xx} >> FF",
	]
	obj = {
		"path": exe_name,
		"switches": [
			{
				"title": "Patch to EPPL Mod \n(remove piston push limit)",
				"patches": patches,
			}
		]
	}
	am_cfg.write_text(json.dumps(obj, indent=4), encoding='utf-8')


# ---------- MAIN ----------
def pick_file_interactive() -> Path:
	"""Ask user for method: type path or file picker. Returns Path or None."""
	while True:
		print("Experemental EPPl auto patcher for MCBE UWP x64/x86 created by MaxRM.")
		print("Select file input method:")
		print("  1) Type full path")
		print("  2) File picker (Windows Explorer)")
		choice = input("Enter 1 or 2: ").strip()
		if choice == '1':
			user_input = input("Enter path to binary file: ").strip().strip('"')
			p = Path(user_input)
			if p.exists():
				return p
			print("File not found, try again.\n")
		elif choice == '2':
			if not tk_available:
				print("File picker is not available, falling back to typing path.\n")
				continue
			root = tk.Tk()
			root.withdraw()
			filetypes = [("Executable files", "*.exe"), ("All files", "*.*")]
			p = filedialog.askopenfilename(title="Select EXE file", filetypes=filetypes)
			root.destroy()
			if p:
				pp = Path(p)
				if pp.exists():
					return pp
				print("Selected file does not exist, try again.\n")
			else:
				print("No file selected, try again.\n")
		else:
			print("Invalid choice, try again.\n")


def main():
	project_root = Path(__file__).resolve().parent
	cfg_path = project_root / 'config.json'
	if not cfg_path.exists():
		print("config.json not found at project root.")
		return

	try:
		top_cfg = read_top_config(cfg_path)
	except Exception as e:
		print("Error in config.json:", e)
		return

	# File selection
	file_path = pick_file_interactive()
	if not file_path:
		print("No file selected. Exiting.")
		return

	# Detect arch
	try:
		arch = detect_pe_arch(file_path)
		print(f"Detected PE architecture: {arch}")
	except Exception as e:
		print("Failed to detect PE architecture:", e)
		return

	sect = top_cfg[arch]
	patternA = sect["patternA"]
	range_str = str(sect["range"])
	patternB = sect["patternB"]
	xx_opts = sect["xxOptions"]

	# Search
	try:
		results, filesize = search_xx_offsets(file_path, patternA, range_str, patternB, xx_opts)
	except Exception as e:
		print("Search failed:", e)
		return

	print(f"File: {file_path}  Size: {filesize} bytes")
	print(f"patternA={len(parse_hex_pattern(patternA)[0])} bytes  patternB={len(parse_hex_pattern(patternB)[0])} bytes  range={range_str}")

	if not results:
		print("No matches found.")
		return

	# Deduplicate offsets if the same offset found with different option (shouldn't happen, but safe)
	dedup = {}
	for off, xx in results:
		dedup.setdefault(off, xx)
	results_unique = sorted([(off, xx) for off, xx in dedup.items()], key=lambda x: x[0])

	# Report offsets of XX only
	print(f"Found {len(results_unique)} XX offsets:")
	for i, (off, xx) in enumerate(results_unique, 1):
		print(f"{i}. XX at {format_off(off)} (matched {xx})")
	# Additionally print raw offsets only
	for off, _xx in results_unique:
		print(f"{format_off(off)}")

	# Validate count
	count = len(results_unique)
	if count != 2:
		if count == 1:
			print("Error: exactly two results required, got 1.")
		elif count >= 3:
			print(f"Error: too many results ({count}). Exactly two required.")
		return

	# Success: write HexOffsets.txt next to the target EXE
	first_off, first_xx = results_unique[0]
	second_off, second_xx = results_unique[1]
	try:
		off_file = file_path.parent / 'HexOffsets.txt'
		from datetime import datetime
		timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		content = f"{format_off(first_off)}\n{format_off(second_off)}\n{timestamp}\n"
		off_file.write_text(content, encoding='utf-8')
	except Exception as e:
		print("Warning: failed to write HexOffsets.txt:", e)

	# Ask user whether to copy AutoModificator assets and update config
	resp = input("Copy AutoModificator and update it's config next to the EXE? [y/N]: ").strip().lower()
	if resp not in ('y', 'yes'):
		print("Copy skipped.")
		return

	# Proceed: copy AutoModificator assets and write it's config
	try:
		copy_am_assets(project_root, arch, file_path.parent)
		write_am_config(file_path.parent, file_path.name, first_off, first_xx, second_off, second_xx)
		print("AutoModificator assets copied and config.json updated successfully.")
	except Exception as e:
		print("Failed to copy AutoModificator or write it's config:", e)
		return
	# Experemental EPPl auto patcher for MCBE UWP x64/x86 created by MaxRM.

if __name__ == "__main__":
	main() 