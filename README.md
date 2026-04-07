# ElGamal 2048-bit

App Python de tao khoa, ma hoa, giai ma, ky va kiem tra chu ky bang he mat ElGamal voi modulo 2048-bit.
Phan thong diep van ban cho ben gui/ben nhan duoc so hoa theo bang chu cai `A-Z`: doi sang chu in hoa, bo qua ky tu khong nam trong `A-Z`, sau do duyet lan luot theo cong thuc `value = value * 26 + vi_tri_ky_tu`.

## Chay nhanh

```powershell
python main.py genkey -o mykey
python main.py encrypt --key mykey.public.json --message "Xin chao" --outfile cipher.json
python main.py decrypt --key mykey.private.json --infile cipher.json
python main.py sign --key mykey.private.json --message "Xin chao" --outfile signature.json
python main.py verify --key mykey.public.json --signature signature.json --message "Xin chao"
```

Thong diep `"Xin chao"` se duoc chuan hoa thanh `XINCHAO` truoc khi ma hoa.

## Giai thich file

- `main.py`: ung dung CLI va menu tuong tac.
- `*.public.json`: khoa cong khai.
- `*.private.json`: khoa bi mat.
- `cipher.json`: ban ma duoi dang JSON.
- `signature.json`: chu ky so duoi dang JSON.

## Luu y

- App dung nhom modulo 2048-bit chuan RFC 3526, generator `g = 2`.
- Luong thong diep van ban duoc ma hoa theo khoi ky tu `A-Z` su dung bieu dien co so 26.
- Ma hoa file van duoi dang chia khoi bytes, moi khoi duoc ma hoa rieng.
- Khi giai ma ma khong truyen `--outfile`, du lieu nhi phan se duoc in ra man hinh bang Base64. Them `--text` neu plaintext la UTF-8.
- Menu mac dinh da tach vai tro `Ben gui` va `Ben nhan` de thao tac nhanh voi thong diep van ban.
