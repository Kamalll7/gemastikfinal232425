# xl — patch guide

**Challenge:** xl (2023, Web)
**Primary source:** `gemastik-xvi-final/services/xl/src/app.controller.ts & app.service.ts`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Arbitrary File Read (LFI) lewat Injeksi Opsi Query ?type=file pada xlsx.read()
- **Status:** VALID / High / confidence High / CWE-73
- **Root cause:** Attacker meng-upload sebuah file kecil yang isinya hanya teks `/flag.txt`, lalu memanggil URL `POST /?type=file`. Library `xlsx` melihat opsi `type: 'file'`, membaca teks `/flag.txt` dari dalam `file.buffer`, membuka file `/flag.txt` milik server, dan mengembalikan isinya sebagai JSON ke layar attacker!
- **Exploit page:** `exploits/xl/exploit.py`

**Vulnerable pattern**
```text
// Di app.controller.ts:
@Post()
@UseInterceptors(FileInterceptor('file'))
convert(@UploadedFile() file: Express.Multer.File, @Query() options: ParsingOptions) {
  return this.appService.convert(file, options);
}

// Di app.service.ts:
convert(file, options): object {
  return read(file.buffer, options).Sheets;
}
```

**Patched pattern**
```text
// Di app.service.ts: Kunci paksa opsi menjadi { type: 'buffer' } dan abaikan options dari user!
convert(file: Express.Multer.File, _options?: ParsingOptions): object {
  return read(file.buffer, { type: 'buffer' }).Sheets;
}
```

**Verification**
- Ignore user-supplied parsing options and force `{type:'buffer'}`.
- Validate the uploaded file type and reject path-like content.
- `?type=file` must not read server files; normal spreadsheets must still parse.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvi-final/services/xl
patch -p1 --dry-run < ../../../patches/fix-buffer-type.diff
patch -p1 < ../../../patches/fix-buffer-type.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
