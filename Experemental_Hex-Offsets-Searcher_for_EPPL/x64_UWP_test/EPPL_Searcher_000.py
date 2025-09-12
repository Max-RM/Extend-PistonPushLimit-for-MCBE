#!/usr/bin/env python3
import re
from pathlib import Path

# ---------- UTILS ----------
def parse_hex_pattern(line: str):
    tokens = re.split(r'[\s,]+', line.strip())
    out = []
    for t in tokens:
        if not t:
            continue
        if len(t) == 1:
            t = '0' + t
        if len(t) != 2:
            raise ValueError(f"Неправильный токен: '{t}'")
        hi, lo = t[0].upper(), t[1].upper()
        mask, val = 0, 0
        if hi != '?':
            mask |= 0xF0
            val |= int(hi, 16) << 4
        if lo != '?':
            mask |= 0x0F
            val |= int(lo, 16)
        out.append((mask, val))
    return out

def match_at(data: bytes, pos: int, pattern):
    if pos < 0 or pos + len(pattern) > len(data):
        return False
    for i, (mask, val) in enumerate(pattern):
        if (data[pos + i] & mask) != val:
            return False
    return True

# ---------- CONFIG ----------
def read_config(path: Path):
    lines = [ln.strip() for ln in path.read_text(encoding='utf-8', errors='ignore').splitlines() if ln.strip()]
    if len(lines) < 3:
        raise ValueError("config.txt должен содержать 3 строки: patternA, range, patternB")
    patA = parse_hex_pattern(lines[0])
    m = re.findall(r'\d+', lines[1])
    if not m:
        raise ValueError("В строке диапазона нет чисел")
    min_gap, max_gap = (int(m[0]), int(m[0])) if len(m) == 1 else (min(int(m[0]), int(m[1])), max(int(m[0]), int(m[1])))
    patB = parse_hex_pattern(lines[2])
    return patA, min_gap, max_gap, patB

# ---------- SEARCH ----------
def search_file(file_path: Path, patA, min_gap, max_gap, patB):
    data = file_path.read_bytes()
    n = len(data)
    results = []
    lenA, lenB = len(patA), len(patB)
    pos = 0
    while pos + lenA <= n:
        if match_at(data, pos, patA):
            base = pos + lenA
            for gap in range(min_gap, max_gap + 1):
                j = base + gap
                if j + lenB <= n and match_at(data, j, patB):
                    results.append((pos, j + lenB - 1, gap, pos, j))
            pos += 1
        else:
            pos += 1
    return results, n

def format_off(x): return f"0x{x:08X}"

# ---------- MAIN ----------
def main():
    cfg = Path("config.txt")
    if not cfg.exists():
        print("config.txt не найден.")
        return

    try:
        patA, min_gap, max_gap, patB = read_config(cfg)
    except Exception as e:
        print("Ошибка в config.txt:", e)
        return

    # запрос пути к файлу
    while True:
        user_input = input("Введите путь к бинарному файлу: ").strip().strip('"')
        file_path = Path(user_input)
        if file_path.exists():
            break
        print("Файл не найден, попробуйте снова.")

    results, filesize = search_file(file_path, patA, min_gap, max_gap, patB)

    out_lines = []
    header = f"Файл: {file_path}  Размер: {filesize} байт\nPatternA={len(patA)} байт  PatternB={len(patB)} байт  gap={min_gap}-{max_gap}\n"
    print(header)
    out_lines.append(header)

    if not results:
        msg = "Совпадений не найдено."
        print(msg)
        out_lines.append(msg)
    else:
        print(f"Найдено {len(results)} совпадений:\n")
        out_lines.append(f"Найдено {len(results)} совпадений:\n")
        for i, (start, end_incl, gap, posA, posB) in enumerate(results, 1):
            line = f"{i}. start={format_off(start)}, end={format_off(end_incl)}, gap={gap}, posA={format_off(posA)}, posB={format_off(posB)}"
            print(line)
            out_lines.append(line)

    Path("output.txt").write_text("\n".join(out_lines), encoding="utf-8")
    print("\nРезультаты сохранены в output.txt")

if __name__ == "__main__":
    main()
