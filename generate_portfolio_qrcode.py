"""
Pure Python QR Code Generator for Tohon Fourier's Portfolio
Generates:
 - qrcode_portfolio.png (Standard contrast, 592x592 px)
 - qrcode_portfolio_cyber.png (Cyberpunk Matrix green theme)
 - qrcode_portfolio.svg (Vector format for printing)
 - badge_qr_portfolio.html (Interactive printable business card)
Zero external dependencies (Python standard library only).
"""

import zlib
import struct
import os

URL = "https://calderafourier-code.github.io/"

def generate_qr_matrix(text):
    size = 29 # Version 3 (29x29)
    raw = text.encode('iso-8859-1')
    
    # 1. Mode indicator (0100 for 8-bit Byte mode) + 8-bit length
    bits = [0, 1, 0, 0]
    l = len(raw)
    for i in range(7, -1, -1):
        bits.append((l >> i) & 1)
    for b in raw:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
            
    # Terminator (up to 4 zeroes)
    term = min(4, 44 * 8 - len(bits))
    bits.extend([0] * term)
    
    # Pad to byte boundary
    while len(bits) % 8 != 0:
        bits.append(0)
        
    # Data bytes
    data_bytes = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        data_bytes.append(byte)
        
    # Pad bytes up to 44 codewords (V3-M capacity)
    pads = [0xEC, 0x11]
    p_idx = 0
    while len(data_bytes) < 44:
        data_bytes.append(pads[p_idx])
        p_idx = (p_idx + 1) % 2

    # GF(256) tables for Reed-Solomon (primitive poly 0x11d)
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        exp[i + 255] = x
        log[x] = i
        x = (x << 1) ^ (0x11d if (x & 0x80) else 0)

    def gf_mul(a, b):
        return 0 if a == 0 or b == 0 else exp[(log[a] + log[b]) % 255]

    # RS generator polynomial for 26 EC codewords
    poly = [1]
    for i in range(26):
        new_poly = [0] * (len(poly) + 1)
        for j in range(len(poly)):
            new_poly[j] ^= gf_mul(poly[j], exp[i])
            new_poly[j + 1] ^= poly[j]
        poly = new_poly
    gen = list(reversed(poly))

    # Divide data by generator polynomial to get EC codewords
    res = list(data_bytes) + [0] * 26
    for i in range(len(data_bytes)):
        coef = res[i]
        if coef != 0:
            for j in range(len(gen)):
                res[i + j] ^= gf_mul(gen[j], coef)
    ec_bytes = res[len(data_bytes):]
    all_codewords = data_bytes + ec_bytes

    # Convert all codewords into bits + 7 remainder bits for V3
    all_bits = []
    for b in all_codewords:
        for i in range(7, -1, -1):
            all_bits.append((b >> i) & 1)
    all_bits.extend([0] * 7) # Remainder bits for V3

    # Matrix templates
    is_func = [[False] * size for _ in range(size)]
    base_grid = [[0] * size for _ in range(size)]

    # 1. Finder patterns & separators
    def add_finder(r0, c0):
        for r in range(-1, 8):
            for c in range(-1, 8):
                r_abs, c_abs = r0 + r, c0 + c
                if 0 <= r_abs < size and 0 <= c_abs < size:
                    is_func[r_abs][c_abs] = True
                    if 0 <= r <= 6 and 0 <= c <= 6:
                        base_grid[r_abs][c_abs] = 1 if (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4)) else 0
                    else:
                        base_grid[r_abs][c_abs] = 0

    add_finder(0, 0)
    add_finder(0, size - 7)
    add_finder(size - 7, 0)

    # 2. Timing patterns
    for i in range(8, size - 8):
        if not is_func[6][i]:
            is_func[6][i] = True
            base_grid[6][i] = 1 if i % 2 == 0 else 0
        if not is_func[i][6]:
            is_func[i][6] = True
            base_grid[i][6] = 1 if i % 2 == 0 else 0

    # 3. Alignment pattern at (22, 22) for V3
    ar, ac = 22, 22
    for r in range(-2, 3):
        for c in range(-2, 3):
            rr, cc = ar + r, ac + c
            if not is_func[rr][cc]:
                is_func[rr][cc] = True
                base_grid[rr][cc] = 1 if (abs(r) == 2 or abs(c) == 2 or (r == 0 and c == 0)) else 0

    # 4. Dark module at (21, 8)
    is_func[size - 8][8] = True
    base_grid[size - 8][8] = 1

    # 5. Reserve format info modules
    for i in range(9):
        is_func[8][i] = True
        is_func[i][8] = True
    for i in range(8):
        is_func[8][size - 1 - i] = True
        is_func[size - 1 - i][8] = True

    # 6. Place data bits in 2-column zig-zag
    data_grid = [row[:] for row in base_grid]
    bit_idx = 0
    c = size - 1
    going_up = True
    while c > 0:
        if c == 6: # Skip timing column
            c -= 1
        rows = range(size - 1, -1, -1) if going_up else range(size)
        for r in rows:
            for cc in (c, c - 1):
                if not is_func[r][cc]:
                    if bit_idx < len(all_bits):
                        data_grid[r][cc] = all_bits[bit_idx]
                        bit_idx += 1
                    else:
                        data_grid[r][cc] = 0
        going_up = not going_up
        c -= 2

    # 7. Masking formulas (0 to 7)
    masks = [
        lambda r, c: (r + c) % 2 == 0,
        lambda r, c: r % 2 == 0,
        lambda r, c: c % 3 == 0,
        lambda r, c: (r + c) % 3 == 0,
        lambda r, c: (r // 2 + c // 3) % 2 == 0,
        lambda r, c: ((r * c) % 2) + ((r * c) % 3) == 0,
        lambda r, c: (((r * c) % 2) + ((r * c) % 3)) % 2 == 0,
        lambda r, c: (((r + c) % 2) + ((r * c) % 3)) % 2 == 0,
    ]

    # Format info BCH calculator for ECL M (00)
    def get_format_bits(mask_idx):
        val = (0 << 3) | mask_idx # ECL M = 00
        rem = val << 10
        poly = 0x537
        for i in range(4, -1, -1):
            if (rem >> (i + 10)) & 1:
                rem ^= poly << i
        fmt = ((val << 10) | rem) ^ 0x5412
        return [(fmt >> (14 - i)) & 1 for i in range(15)]

    tl_coords = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8), (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    br_coords = [(size - 1 - i, 8) for i in range(7)] + [(8, size - 8 + i) for i in range(8)]

    # 8. Evaluate penalties for each mask to find the best one
    def calc_penalty(g):
        p = 0
        # N1: 5 or more consecutive of same color
        for r in range(size):
            run_color = g[r][0]
            run_len = 1
            for c in range(1, size):
                if g[r][c] == run_color:
                    run_len += 1
                else:
                    if run_len >= 5:
                        p += 3 + (run_len - 5)
                    run_color = g[r][c]
                    run_len = 1
            if run_len >= 5:
                p += 3 + (run_len - 5)

        for c in range(size):
            run_color = g[0][c]
            run_len = 1
            for r in range(1, size):
                if g[r][c] == run_color:
                    run_len += 1
                else:
                    if run_len >= 5:
                        p += 3 + (run_len - 5)
                    run_color = g[r][c]
                    run_len = 1
            if run_len >= 5:
                p += 3 + (run_len - 5)

        # N2: 2x2 blocks of same color
        for r in range(size - 1):
            for c in range(size - 1):
                if g[r][c] == g[r+1][c] == g[r][c+1] == g[r+1][c+1]:
                    p += 3

        # N4: Balance of dark / light modules
        dark_count = sum(row.count(1) for row in g)
        ratio = (dark_count * 100) // (size * size)
        k = abs(ratio - 50) // 5
        p += k * 10
        return p

    best_mask = 0
    best_penalty = 10**9
    best_grid = None

    for m_idx, mask_fn in enumerate(masks):
        candidate = [row[:] for row in data_grid]
        for r in range(size):
            for c in range(size):
                if not is_func[r][c]:
                    if mask_fn(r, c):
                        candidate[r][c] ^= 1

        f_bits = get_format_bits(m_idx)
        for i, (r, c) in enumerate(tl_coords):
            candidate[r][c] = f_bits[i]
        for i, (r, c) in enumerate(br_coords):
            candidate[r][c] = f_bits[i]

        pen = calc_penalty(candidate)
        if pen < best_penalty:
            best_penalty = pen
            best_mask = m_idx
            best_grid = candidate

    return best_grid


def save_png(filename, grid, module_size=16, quiet_zone=4, fg=(0, 0, 0), bg=(255, 255, 255)):
    n = len(grid)
    width = (n + 2 * quiet_zone) * module_size
    height = width
    raw = bytearray()
    
    for y in range(height):
        raw.append(0) # Filter type 0
        my = (y // module_size) - quiet_zone
        for x in range(width):
            mx = (x // module_size) - quiet_zone
            if 0 <= my < n and 0 <= mx < n and grid[my][mx] == 1:
                raw.extend(fg)
            else:
                raw.extend(bg)
                
    compressed = zlib.compress(bytes(raw), 9)
    
    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)
        
    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', compressed)
    png += chunk(b'IEND', b'')
    
    with open(filename, 'wb') as f:
        f.write(png)


def save_svg(filename, grid, quiet_zone=4, fg="#000000", bg="#ffffff"):
    n = len(grid)
    total_size = n + 2 * quiet_zone
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_size} {total_size}" shape-rendering="crispEdges">',
        f'<rect width="{total_size}" height="{total_size}" fill="{bg}"/>',
    ]
    for r in range(n):
        for c in range(n):
            if grid[r][c] == 1:
                svg.append(f'<rect x="{c + quiet_zone}" y="{r + quiet_zone}" width="1" height="1" fill="{fg}"/>')
    svg.append('</svg>')
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(svg))


if __name__ == "__main__":
    grid = generate_qr_matrix(URL)
    
    # 1. Standard QR Code PNG (black on white, 592x592)
    save_png("qrcode_portfolio.png", grid, module_size=16, quiet_zone=4, fg=(0, 0, 0), bg=(255, 255, 255))
    
    # 2. Cyberpunk Matrix Green QR Code PNG
    save_png("qrcode_portfolio_cyber.png", grid, module_size=16, quiet_zone=4, fg=(0, 255, 65), bg=(10, 10, 10))
    
    # 3. Scalable Vector Graphics (SVG)
    save_svg("qrcode_portfolio.svg", grid, quiet_zone=4, fg="#000000", bg="#ffffff")
    save_svg("qrcode_portfolio_cyber.svg", grid, quiet_zone=4, fg="#00ff41", bg="#0a0a0a")
    
    print("ALL QR CODES GENERATED SUCCESSFULLY!")
