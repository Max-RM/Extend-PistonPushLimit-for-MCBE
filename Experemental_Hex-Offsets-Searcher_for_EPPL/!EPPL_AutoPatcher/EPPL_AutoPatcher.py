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
	"""Reads root config.json with arch sections and global flags.
	Expected structure:
	{
	  "writeHexOffsetsToWorkDir": true | false | "ask",
	  "x86": {"patternA": "..", "range": "min-max", "patternB": "..", "xxOptions": {"0C": true, "0D": true, "FF": true}},
	  "x64": { ... },
	  "arm32": { ... },
	  "arm64": { ... }
	}
	"""
	try:
		cfg_obj = json.loads(cfg_path.read_text(encoding='utf-8'))
	except Exception as e:
		raise ValueError(f"Failed to read config.json: {e}")
	# Global flag (optional, tri-state)
	write_flag = cfg_obj.get("writeHexOffsetsToWorkDir", False)
	if not (isinstance(write_flag, bool) or write_flag == "ask"):
		raise ValueError("'writeHexOffsetsToWorkDir' must be boolean or 'ask' if present")
	# Validate any present arch sections
	for arch in ("x86", "x64", "arm32", "arm64"):
		if arch in cfg_obj:
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
	# Attach normalized flag
	cfg_obj["writeHexOffsetsToWorkDir"] = write_flag
	# Backward compatibility: accept old key if present
	if "writeOffsetsToBinaryDir" in cfg_obj and "writeHexOffsetsToWorkDir" not in cfg_obj:
		old = cfg_obj["writeOffsetsToBinaryDir"]
		if isinstance(old, bool):
			cfg_obj["writeHexOffsetsToWorkDir"] = old
	return cfg_obj


# ---------- PE ARCH DETECTION ----------
def detect_pe_arch(exe_path: Path) -> str:
	"""Returns 'x86', 'x64', 'arm32' or 'arm64' by reading PE headers.
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
	elif machine in (0x01C0, 0x01C4):  # ARM / ARMNT
		return 'arm32'
	elif machine == 0xAA64:  # ARM64
		return 'arm64'
	else:
		raise ValueError(f"Unsupported PE machine: 0x{machine:04X}")


# ---------- SEARCH ----------
def search_xx_offsets(file_path: Path, patternA_str: str, gap_range_str: str, patternB_str: str, allowed_xx_vals):
	"""Search for patternA, then patternB within [min,max] gap.
	patternB may contain one 'XX' placeholder. For each allowed XX value, try to match; if matched, record:
	- absolute offset of the XX byte
	- the actual matched XX value (as '0C'/'0D'/'FF')
	- the next byte value after XX (as two-digit hex string), or None if out of range
	Returns (results, filesize) where results is list of tuples (xx_offset, xx_value_hex_str, next_byte_hex_or_none).
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
						next_hex = None
						if xx_abs + 1 < n:
							next_hex = f"{data[xx_abs + 1]:02X}"
						results.append((xx_abs, key, next_hex))
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


def build_patches_for_arch(arch: str, first_tuple, second_tuple):
	"""Return patches array depending on architecture.
	- For arm32: 4 entries using next-byte values in place of '??'.
	- Others: 2 entries with 'FF' as final byte and XX marker.
	"""
	first_off, first_xx, first_next = first_tuple
	second_off, second_xx, second_next = second_tuple
	if arch == 'arm32':
		# Fallback to '??' if next byte is unavailable
		n1 = first_next if first_next is not None else '??'
		n2 = second_next if second_next is not None else '??'
		return [
			f"{format_off(first_off)} >> {first_xx} >> 01",
			f"{format_off(first_off + 1)} >> {n1} >> 20",
			f"{format_off(second_off)} >> {second_xx} >> 01",
			f"{format_off(second_off + 1)} >> {n2} >> 20",
		]
	else:
		return [
			f"{format_off(first_off)} >> {first_xx} >> FF",
			f"{format_off(second_off)} >> {second_xx} >> FF",
		]


def write_am_config(dest_dir: Path, exe_name: str, arch: str, first_tuple, second_tuple):
	"""Rewrite AM config.json in dest_dir to required structure."""
	am_cfg = dest_dir / 'config.json'
	patches = build_patches_for_arch(arch, first_tuple, second_tuple)
	obj = {
		"path": exe_name,
		"switches": [
			{
				"title": "Patch to EPPL Mod (remove piston push limit)",
				"patches": patches,
			}
		]
	}
	am_cfg.write_text(json.dumps(obj, indent=4), encoding='utf-8')


# ---------- MAIN ----------
def pick_file_interactive() -> Path:
	"""Ask user for method: file picker or type path. Returns Path or None."""
	while True:
		print("Experemental EPPL AutoPatcher v 001 for MCBE UWP created by MaxRM")
		print("Select file input method:")
		print("  1) File picker (Windows Explorer)")
		print("  2) Type full path")
		choice = input("Enter 1 or 2: ").strip()
		if choice == '1':
			if not tk_available:
				print("File picker is not available, falling back to typing path.\n")
				choice = '2'
			else:
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
		if choice == '2':
			user_input = input("Enter path to binary file: ").strip().strip('"')
			p = Path(user_input)
			if p.exists():
				return p
			print("File not found, try again.\n")
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

	if arch not in top_cfg:
		print(f"No config section for architecture '{arch}'.")
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
	for off, xx, nxt in results:
		if off not in dedup:
			dedup[off] = (off, xx, nxt)
	results_unique = sorted(list(dedup.values()), key=lambda x: x[0])

	# Report offsets of XX only
	print(f"Found {len(results_unique)} XX offsets:")
	for i, (off, xx, _nxt) in enumerate(results_unique, 1):
		print(f"{i}. XX at {format_off(off)} (matched {xx})")
	# Additionally print raw offsets only
	for off, _xx, _nxt in results_unique:
		print(f"{format_off(off)}")

	# Write HexOffsets.txt always in script directory; optionally also in binary directory based on tri-state flag
	from datetime import datetime
	lines = [format_off(off) for off, _xx, _nxt in results_unique]
	lines.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
	local_off = project_root / 'HexOffsets.txt'
	try:
		local_off.write_text("\n".join(lines) + "\n", encoding='utf-8')
		flag = top_cfg.get('writeHexOffsetsToWorkDir', False)
		write_work = False
		if flag is True:
			write_work = True
		elif flag == 'ask':
			resp = input("Also write HexOffsets.txt next to the EXE? [y/N]: ").strip().lower()
			write_work = resp in ('y', 'yes')
		if write_work:
			(file_path.parent / 'HexOffsets.txt').write_text("\n".join(lines) + "\n", encoding='utf-8')
	except Exception as e:
		print("Warning: failed to write HexOffsets.txt:", e)

	# Validate count
	count = len(results_unique)
	if count != 2:
		if count == 1:
			print("Error: exactly two results required, got 1.")
		elif count >= 3:
			print(f"Error: too many results ({count}). Exactly two required.")
		return

	# Ask user whether to copy AutoModificator assets and update AutoModificator config
	resp = input("Copy AutoModificator assets and update AutoModificator config next to the EXE? [y/N]: ").strip().lower()
	if resp not in ('y', 'yes'):
		print("Copy skipped.")
		return

	# Proceed: copy AutoModificator assets and write AutoModificator config
	first_tuple = results_unique[0]
	second_tuple = results_unique[1]
	try:
		copy_am_assets(project_root, arch, file_path.parent)
		write_am_config(file_path.parent, file_path.name, arch, first_tuple, second_tuple)
		print("AutoModificator assets copied and config.json updated successfully.")
	except Exception as e:
		print("Failed to copy AutoModificator or write it's config:", e)
		return
	# Experemental EPPL AutoPatcher v 001 for MCBE UWP created by MaxRM.

if __name__ == "__main__":
	main() 