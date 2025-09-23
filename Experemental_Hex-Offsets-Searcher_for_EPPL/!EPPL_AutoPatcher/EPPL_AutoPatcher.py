#!/usr/bin/env python3
import json
import re
import shutil
from pathlib import Path

# UI and platform
try:
	import tkinter as tk
	from tkinter import filedialog
	tk_available = True
except Exception:
	tk_available = False

import ctypes
from ctypes import wintypes
import ctypes
import psutil

# ---------- Small utils ----------
def format_hex_off(x: int) -> str:
	return f"0x{x:08X}"


def ask(prompt: str, valid: set):
	while True:
		v = input(prompt).strip().lower()
		if v in valid:
			return v
		print("Invalid choice.\n")

# ---------- Config ----------
def read_top_config(cfg_path: Path):
	cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
	# normalize tri-states
	for k in ("writeHexOffsetsToWorkDir", "RAMPatchMode"):
		v = cfg.get(k, False)
		if not (isinstance(v, bool) or v == 'ask'):
			raise ValueError(f"'{k}' must be boolean or 'ask'")
		cfg[k] = v
	kw = cfg.get("RAMProcessKeywords", [])
	cfg["RAMProcessKeywords"] = [str(s) for s in kw] if isinstance(kw, list) else []
	# validate arch sections
	for arch in ("x86", "x64", "arm32", "arm64"):
		if arch in cfg:
			sect = cfg[arch]
			for key in ("patternA", "range", "patternB", "xxOptions"):
				if key not in sect:
					raise ValueError(f"Missing '{key}' in {arch}")
			m = re.findall(r"\d+", str(sect['range']))
			if not m:
				raise ValueError(f"Range has no numbers in {arch}")
			# xxOptions may include 0120 for arm32
			if not isinstance(sect['xxOptions'], dict):
				raise ValueError(f"xxOptions must be dict in {arch}")
	return cfg

# ---------- Pattern parsing ----------
def parse_hex_pattern(pattern_str: str):
	tokens = re.split(r"[\s,]+", pattern_str.strip())
	pattern = []
	xx_index = None
	for tok in tokens:
		if not tok:
			continue
		t = tok.upper()
		if t == 'XX':
			if xx_index is not None:
				raise ValueError("Only one XX allowed in patternB")
			xx_index = len(pattern)
			pattern.append((0x00, 0x00))
			continue
		if len(t) == 1:
			t = '0' + t
		if len(t) != 2:
			raise ValueError(f"Invalid token '{tok}'")
		hi, lo = t[0], t[1]
		mask = 0
		val = 0
		if hi != '?':
			mask |= 0xF0
			val |= int(hi, 16) << 4
		if lo != '?':
			mask |= 0x0F
			val |= int(lo, 16)
		pattern.append((mask, val))
	return pattern, xx_index


def match_at(buf: bytes, pos: int, pattern):
	if pos < 0 or pos + len(pattern) > len(buf):
		return False
	for i, (mask, val) in enumerate(pattern):
		if (buf[pos + i] & mask) != val:
			return False
	return True

# ---------- File arch ----------
def detect_pe_arch(exe_path: Path) -> str:
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
	elif machine in (0x01C0, 0x01C4):
		return 'arm32'
	elif machine == 0xAA64:
		return 'arm64'
	else:
		raise ValueError(f"Unsupported PE machine: 0x{machine:04X}")

# ---------- Search core ----------
def search_in_bytes(buf: bytes, patternA: str, range_str: str, patternB: str, xx_opts: dict, arch: str):
	patA, xxA = parse_hex_pattern(patternA)
	if xxA is not None:
		raise ValueError("patternA must not contain XX")
	patB, xxB = parse_hex_pattern(patternB)
	if xxB is None:
		raise ValueError("patternB must contain XX")
	m = re.findall(r"\d+", str(range_str))
	if not m:
		raise ValueError("Range has no numbers")
	min_gap, max_gap = (int(m[0]), int(m[0])) if len(m) == 1 else (min(int(m[0]), int(m[1])), max(int(m[0]), int(m[1])))
	allowed = []
	for key, val in (('0C', 0x0C), ('0D', 0x0D), ('FF', 0xFF)):
		if xx_opts.get(key):
			allowed.append((key, val))
	# arm32 special pair 0120
	allow_0120 = (arch == 'arm32' and bool(xx_opts.get('0120')))
	res = []
	n = len(buf)
	pos = 0
	lenA, lenB = len(patA), len(patB)
	while pos + lenA <= n:
		if match_at(buf, pos, patA):
			base = pos + lenA
			for gap in range(min_gap, max_gap + 1):
				j = base + gap
				if j + lenB > n:
					continue
				# try normal XX values
				for key, val in allowed:
					ok = True
					for i, (mask, mval) in enumerate(patB):
						b = buf[j + i]
						if i == xxB:
							if b != val:
								ok = False
								break
						else:
							if (b & mask) != mval:
								ok = False
								break
					if ok:
						xx_abs = j + xxB
						next_hex = f"{buf[xx_abs+1]:02X}" if xx_abs + 1 < n else None
						res.append((xx_abs, key, next_hex))
				# try arm32 pair (01 20) if enabled
				if allow_0120 and j + xxB + 1 < n:
					ok = True
					for i, (mask, mval) in enumerate(patB):
						b = buf[j + i]
						if i == xxB:
							if b != 0x01 or buf[j + i + 1] != 0x20:
								ok = False
								break
						else:
							if (b & mask) != mval:
								ok = False
								break
					if ok:
						xx_abs = j + xxB
						next_hex = f"{buf[xx_abs+1]:02X}"
						res.append((xx_abs, '0120', next_hex))
		# advance position regardless of match to avoid infinite loop
		pos += 1
	# dedup by offset
	dedup = {}
	for off, xx, nxt in res:
		if off not in dedup:
			dedup[off] = (off, xx, nxt)
	return sorted(dedup.values(), key=lambda x: x[0]), n

# ---------- File helpers ----------
def pick_file_interactive() -> Path:
	while True:
		print("Experemental EPPl auto patcher for MCBE UWP created by MaxRM.")
		print("Select file input method:")
		print("  1) File picker (Windows Explorer)")
		print("  2) Type full path")
		print("  3) Back to main menu")
		print("  4) Exit program")
		c = input("Enter 1-4: ").strip()
		if c == '1':
			if not tk_available:
				print("File picker is not available.\n")
				continue
			root = tk.Tk(); root.withdraw()
			p = filedialog.askopenfilename(title="Select EXE file", filetypes=[("Executable files", "*.exe"), ("All files", "*.*")])
			root.destroy()
			if p:
				pp = Path(p)
				if pp.exists():
					return pp
				print("Selected file does not exist.\n")
		elif c == '2':
			p = Path(input("Enter path to binary file: ").strip().strip('"'))
			if p.exists():
				return p
			print("File not found.\n")
		elif c == '3':
			return None
		elif c == '4':
			raise SystemExit(0)
		else:
			print("Invalid choice.\n")

# ---------- AM assets ----------
def copy_am_assets(project_root: Path, arch: str, target_dir: Path):
	src = project_root / 'AM' / arch
	if not src.exists():
		raise FileNotFoundError(f"AM/{arch} not found: {src}")
	for item in src.iterdir():
		d = target_dir / item.name
		if item.is_dir():
			if d.exists():
				shutil.rmtree(d)
			shutil.copytree(item, d)
		else:
			shutil.copy2(item, d)


def build_patches_for_arch(arch: str, first_tuple, second_tuple):
	f_off, f_xx, f_next = first_tuple
	s_off, s_xx, s_next = second_tuple
	if arch == 'arm32':
		n1 = f_next if f_next is not None else '??'
		n2 = s_next if s_next is not None else '??'
		return [
			f"{format_hex_off(f_off)} >> {f_xx if f_xx!='0120' else '01'} >> 01",
			f"{format_hex_off(f_off + 1)} >> {n1 if f_xx!='0120' else '20'} >> 20",
			f"{format_hex_off(s_off)} >> {s_xx if s_xx!='0120' else '01'} >> 01",
			f"{format_hex_off(s_off + 1)} >> {n2 if s_xx!='0120' else '20'} >> 20",
		]
	else:
		return [
			f"{format_hex_off(f_off)} >> {f_xx} >> FF",
			f"{format_hex_off(s_off)} >> {s_xx} >> FF",
		]


def write_am_config(dest_dir: Path, exe_name: str, arch: str, first_tuple, second_tuple):
	obj = {
		"path": exe_name,
		"switches": [
			{
				"title": "Patch to EPPL Mod \n(remove piston push limit)",
				"patches": build_patches_for_arch(arch, first_tuple, second_tuple)
			}
		]
	}
	(dest_dir / 'config.json').write_text(json.dumps(obj, indent=4), encoding='utf-8')

# ---------- Windows RAM helpers ----------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

class MODULEENTRY32(ctypes.Structure):
	_fields_ = [
		('dwSize', wintypes.DWORD),
		('th32ModuleID', wintypes.DWORD),
		('th32ProcessID', wintypes.DWORD),
		('GlblcntUsage', wintypes.DWORD),
		('ProccntUsage', wintypes.DWORD),
		('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
		('modBaseSize', wintypes.DWORD),
		('hModule', wintypes.HMODULE),
		('szModule', ctypes.c_char * 256),
		('szExePath', ctypes.c_char * 260),
	]

CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
Module32First = ctypes.windll.kernel32.Module32First
Module32Next = ctypes.windll.kernel32.Module32Next
OpenProcess = ctypes.windll.kernel32.OpenProcess
CloseHandle = ctypes.windll.kernel32.CloseHandle
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory


def enumerate_modules(pid):
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
	if snap == ctypes.c_void_p(-1).value:
		raise OSError("CreateToolhelp32Snapshot failed")
	try:
		me32 = MODULEENTRY32(); me32.dwSize = ctypes.sizeof(MODULEENTRY32)
		if not Module32First(snap, ctypes.byref(me32)):
			raise OSError("Module32First failed")
		mods = []
		while True:
			base = ctypes.addressof(me32.modBaseAddr.contents)
			size = me32.modBaseSize
			name = me32.szModule.decode(errors='ignore')
			path = me32.szExePath.decode(errors='ignore')
			mods.append((base, size, name, path))
			if not Module32Next(snap, ctypes.byref(me32)):
				break
		return mods
	finally:
		CloseHandle(snap)


def read_process_memory(pid, base, size):
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
	if not hProc:
		raise OSError("OpenProcess failed")
	try:
		buf = (ctypes.c_ubyte * size)()
		read = ctypes.c_size_t()
		if not ReadProcessMemory(hProc, ctypes.c_void_p(base), buf, ctypes.c_size_t(size), ctypes.byref(read)):
			raise OSError("ReadProcessMemory failed")
		return bytes(buf)[:read.value]
	finally:
		CloseHandle(hProc)


def write_process_memory(pid, addr, data_bytes: bytes):
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, False, pid)
	if not hProc:
		raise OSError("OpenProcess (write) failed")
	try:
		written = ctypes.c_size_t()
		buf = (ctypes.c_ubyte * len(data_bytes)).from_buffer_copy(data_bytes)
		if not WriteProcessMemory(hProc, ctypes.c_void_p(addr), buf, ctypes.c_size_t(len(data_bytes)), ctypes.byref(written)):
			raise OSError("WriteProcessMemory failed")
		return written.value == len(data_bytes)
	finally:
		CloseHandle(hProc)

# ---------- RAM utilities ----------
def find_candidate_processes(keywords):
	keys = [k.lower() for k in keywords if k]
	cands = []
	for p in psutil.process_iter(['pid', 'name', 'exe']):
		try:
			name = (p.info.get('name') or '')
			exe = (p.info.get('exe') or '')
		except Exception:
			name, exe = '', ''
		name_l = name.lower(); exe_l = exe.lower()
		match = True if not keys else any((k in name_l) or (k in exe_l) for k in keys)
		if match:
			label = (Path(exe).name if exe else name) or f"pid_{p.pid}"
			cands.append((p.info.get('pid'), label))
	return cands

# ---------- Workflows ----------
def ram_mode(cfg):
	while True:
		print("Experemental EPPl auto patcher for MCBE UWP created by MaxRM.")
		cands = find_candidate_processes(cfg.get('RAMProcessKeywords', []))
		if not cands:
			print("No processes matched keywords. Returning to main menu.\n")
			return
		print("Matched processes:")
		for idx, (pid, name) in enumerate(cands):
			print(f"  {idx}) {name} (PID {pid})")
		choice = input("Select by index or enter PID: ").strip()
		picked = None
		if choice.isdigit():
			val = int(choice)
			for i, (pid, name) in enumerate(cands):
				if val == i or val == pid:
					picked = (pid, name)
					break
		if not picked:
			print("Invalid selection.\n"); continue
		pid, name = picked
		# Determine arch from exe path if possible
		try:
			exe = Path(psutil.Process(pid).exe())
		except Exception:
			exe = None
		if exe and exe.exists():
			try:
				arch = detect_pe_arch(exe)
			except Exception:
				arch = 'x64'
		else:
			arch = 'x64'
		if arch not in cfg:
			print(f"No config for arch {arch}. Returning to main menu.\n"); return
		sect = cfg[arch]
		# Read memory of main module
		try:
			mods = enumerate_modules(pid)
			# choose main .exe or lowest base
			exe_mods = [m for m in mods if m[3].lower().endswith('.exe')]
			base, size, mname, mpath = min(exe_mods or mods, key=lambda m: m[0])
			buf = read_process_memory(pid, base, size)
		except Exception as e:
			print("Failed to read process memory:", e); continue
		results, _ = search_in_bytes(buf, sect['patternA'], str(sect['range']), sect['patternB'], sect['xxOptions'], arch)
		if not results:
			print("No matches found in RAM. Returning to process list.\n"); continue
		# Display with RVA (no 0x)
		print(f"Found {len(results)} XX offsets in RAM:")
		proc_name = Path(mpath).name if mpath else (name if name else 'process')
		for i, (off, xx, _nxt) in enumerate(results, 1):
			print(f"{i}. XX at {proc_name}+{off:08X} (matched {xx})")
		for off, _xx, _nxt in results:
			print(f"{proc_name}+{off:08X}")
		# Build RVA lines
		from datetime import datetime
		rva_lines = [f"{proc_name}+{off:08X}" for off, _xx, _nxt in results]
		rva_lines.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
		# Menu
		while True:
			print("Options:")
			print("  1) Patch/unpatch and show status")
			print("  2) Choose another process")
			print("  3) Write RVAOffsets.txt")
			print("  4) Exit to main menu")
			print("  5) Exit program")
			c = input("Enter 1-5: ").strip()
			if c == '1':
				# Status and toggle
				try:
					cur = read_process_memory(pid, base, size)
				except Exception as e:
					print("Failed to read memory for status:", e); continue
				if arch in ('x86','x64'):
					enabled = all(cur[off] == 0xFF for off, _xx, _nxt in results)
					print(f"Current state: {'ENABLED' if enabled else 'DISABLED'}")
					print("Toggle action:")
					print("  1) Enable (write FF)")
					print("  2) Disable (restore 0C)")
					print("  other) Skip")
					act = input("Enter choice: ").strip().lower()
					if act in ('1','y'):
						ok = True
						for off, _xx, _nxt in results:
							ok &= write_process_memory(pid, base + off, b"\xFF")
						print("Enabled" if ok else "Write failed")
					elif act in ('2','n'):
						ok = True
						for off, _xx, _nxt in results:
							ok &= write_process_memory(pid, base + off, b"\x0C")
						print("Disabled (restored 0C)" if ok else "Write failed")
				elif arch == 'arm32':
					enabled = []
					for off, _xx, _nxt in results:
						b0 = cur[off]
						b1 = cur[off+1] if off+1 < len(cur) else 0x00
						enabled.append(b0 == 0x01 and b1 == 0x20)
					print(f"Current state: {'ENABLED' if all(enabled) else 'DISABLED'}")
					print("Toggle action:")
					print("  1) Enable (write 01 20)")
					print("  2) Disable (restore 0C 2B)")
					print("  other) Skip")
					act = input("Enter choice: ").strip().lower()
					if act in ('1','y'):
						ok = True
						for off, _xx, _nxt in results:
							ok &= write_process_memory(pid, base + off, b"\x01\x20")
						print("Enabled" if ok else "Write failed")
					elif act in ('2','n'):
						ok = True
						for off, _xx, _nxt in results:
							ok &= write_process_memory(pid, base + off, b"\x0C\x2B")
						print("Disabled (restored 0C 2B)" if ok else "Write failed")
				else:
					print("RAM patch for this arch is not implemented.")
			elif c == '2':
				break
			elif c == '3':
				try:
					(Path(__file__).resolve().parent / 'RVAOffsets.txt').write_text("\n".join(rva_lines) + "\n", encoding='utf-8')
					print("RVAOffsets.txt written.")
				except Exception as e:
					print("Failed to write RVAOffsets.txt:", e)
			elif c == '4':
				return
			elif c == '5':
				raise SystemExit(0)
			else:
				print("Invalid choice.\n")


def file_mode(cfg):
	project_root = Path(__file__).resolve().parent
	while True:
		p = pick_file_interactive()
		if p is None:
			return
		try:
			arch = detect_pe_arch(p)
			print(f"Detected PE architecture: {arch}")
		except Exception as e:
			print("Failed to detect PE architecture:", e)
			print("Choose:\n  1) Select another file\n  3) Back to main menu\n  4) Exit program")
			c = ask("Enter 1/3/4: ", {'1','3','4'})
			if c == '1':
				continue
			elif c == '3':
				return
			else:
				raise SystemExit(0)
		if arch not in cfg:
			print(f"No config section for architecture '{arch}'.")
			print("Choose:\n  1) Select another file\n  3) Back to main menu\n  4) Exit program")
			c = ask("Enter 1/3/4: ", {'1','3','4'})
			if c == '1':
				continue
			elif c == '3':
				return
			else:
				raise SystemExit(0)
		sect = cfg[arch]
		# search
		buf = p.read_bytes()
		results, size = search_in_bytes(buf, sect['patternA'], str(sect['range']), sect['patternB'], sect['xxOptions'], arch)
		print(f"File: {p}  Size: {size} bytes")
		print(f"patternA={len(parse_hex_pattern(sect['patternA'])[0])} bytes  patternB={len(parse_hex_pattern(sect['patternB'])[0])} bytes  range={sect['range']}")
		if not results:
			print("No matches found.")
			print("Choose:\n  1) Select another file\n  2) Exit\n  3) Back to main menu")
			c = ask("Enter 1-3: ", {'1','2','3'})
			if c == '1':
				continue
			elif c == '3':
				return
			else:
				raise SystemExit(0)
		print(f"Found {len(results)} XX offsets:")
		for i, (off, xx, _nxt) in enumerate(results, 1):
			print(f"{i}. XX at {format_hex_off(off)} (matched {xx})")
		for off, _xx, _nxt in results:
			print(f"{format_hex_off(off)}")
		# write HexOffsets
		from datetime import datetime
		lines = [format_hex_off(off) for off, _xx, _nxt in results]
		lines.append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
		(project_root / 'HexOffsets.txt').write_text("\n".join(lines) + "\n", encoding='utf-8')
		flag = cfg.get('writeHexOffsetsToWorkDir', False)
		write_work = (flag is True) or (flag=='ask' and ask("Also write HexOffsets.txt next to the EXE? [y/N]: ", {'y','n'})=='y')
		if write_work:
			(p.parent / 'HexOffsets.txt').write_text("\n".join(lines) + "\n", encoding='utf-8')
		# validate count
		if len(results) != 2:
			if len(results) == 1:
				print("Error: exactly two results required, got 1.")
			else:
				print(f"Error: too many results ({len(results)}). Exactly two required.")
			print("Choose:\n  1) Select another file\n  2) Exit\n  3) Back to main menu")
			c = ask("Enter 1-3: ", {'1','2','3'})
			if c == '1':
				continue
			elif c == '3':
				return
			else:
				raise SystemExit(0)
		# copy AM
		resp = input("Copy AM assets and update AM config next to the EXE? [y/N]: ").strip().lower()
		if resp not in ('y','yes'):
			print("Copy skipped.")
			print("Choose:\n  1) Select another file\n  2) Exit\n  3) Back to main menu")
			c = ask("Enter 1-3: ", {'1','2','3'})
			if c == '1':
				continue
			elif c == '3':
				return
			else:
				raise SystemExit(0)
		copy_am_assets(project_root, arch, p.parent)
		write_am_config(p.parent, p.name, arch, results[0], results[1])
		print("AutoModificator assets copied and config.json updated successfully.")
		print("Choose:\n  1) Select another file\n  2) Exit\n  3) Back to main menu")
		c = ask("Enter 1-3: ", {'1','2','3'})
		if c == '1':
			continue
		elif c == '3':
			return
		else:
			raise SystemExit(0)

# ---------- Main menu ----------
def main():
	project_root = Path(__file__).resolve().parent
	cfg_path = project_root / 'config.json'
	try:
		cfg = read_top_config(cfg_path)
	except Exception as e:
		print("Error in config.json:", e)
		return
	while True:
		print("Choose mode:")
		print("Experemental EPPl auto patcher for MCBE UWP created by MaxRM.")
		print("  1) Standard file patch (AutoModificator)")
		print("  2) RAM patch mode")
		print("  3) Exit program")
		c = input("Enter 1 or 2: ").strip()
		if c == '1':
			file_mode(cfg)
		elif c == '2':
			ram_mode(cfg)
		elif c == '3':
			return
		else:
			print("Invalid choice.\n")
		
		#Experemental EPPl auto patcher for MCBE UWP created by MaxRM.
		
if __name__ == '__main__':
	main() 