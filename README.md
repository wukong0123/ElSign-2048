# ElGamal 2048-bit

App Python de tao khoa, ma hoa, giai ma, ky va kiem tra chu ky bang he mat ElGamal voi modulo 2048-bit.

## Chay nhanh

```powershell
python main.py genkey -o mykey
python main.py encrypt --key mykey.public.json --message "Xin chao" --outfile cipher.json
python main.py decrypt --key mykey.private.json --infile cipher.json --text
python main.py sign --key mykey.private.json --message "Xin chao" --outfile signature.json
python main.py verify --key mykey.public.json --signature signature.json --message "Xin chao"
```

## Giai thich file

- `main.py`: ung dung CLI va menu tuong tac.
- `*.public.json`: khoa cong khai.
- `*.private.json`: khoa bi mat.
- `cipher.json`: ban ma duoi dang JSON.
- `signature.json`: chu ky so duoi dang JSON.

## Luu y

- App dung nhom modulo 2048-bit chuan RFC 3526, generator `g = 2`.
- Ma hoa file duoi dang chia khoi, moi khoi duoc ma hoa rieng.
- Khi giai ma ma khong truyen `--outfile`, du lieu nhi phan se duoc in ra man hinh bang Base64. Them `--text` neu plaintext la UTF-8.
