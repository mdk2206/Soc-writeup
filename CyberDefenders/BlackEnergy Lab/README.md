# BlackEnergy Lab

## Bối cảnh

Bài Lab mô phỏng một cuộc tấn công mạng nhắm vào một tập đoàn đa quốc gia, dẫn đến việc dữ liệu nhạy cảm bị đánh cắp. Cuộc tấn công sử dụng một biến thể chưa từng được ghi nhận của mã độc BlackEnergy v2. Sau sự cố, đội an ninh của công ty thu thập một bản memory dump từ máy bị nhiễm và nhờ chuyên gia SOC phân tích để hiểu phạm vi và tác động của cuộc tấn công.

Nhiệm vụ của mình là đóng vai SOC analyst: dùng Volatility để phân tích memory dump, xác định hệ điều hành và profile phù hợp, tìm các tiến trình độc hại, kết nối mạng và dấu hiệu code injection hoặc hook hệ thống, từ đó trích xuất các IOCs (tên tiến trình, đường dẫn, địa chỉ IP, driver...) và đánh giá mức độ ảnh hưởng của mã độc đối với máy bị nhiễm.

## Q1: Which volatility profile would be best for this machine?

- Mình dùng plugin `imageinfo` của Volatility 2 để xác định hệ điều hành của memory dump: `vol2 -f YBERDEF-567078-20230213-171333.raw imageinfo`.
- Phần Suggested Profile(s) gợi ý hai profile là `WinXPSP2x86` và `WinXPSP3x86`, trong đó dump được khởi tạo (Instantiated) bằng **WinXPSP2x86**. Mình chọn profile đứng đầu này, rồi kiểm tra lại bằng `pslist` thì danh sách tiến trình hiển thị bình thường.

<img width="1051" height="275" alt="image" src="https://github.com/user-attachments/assets/d9ad1d30-e225-46c7-9c4f-f11bc304d0a6" />

**Đáp án:** `WinXPSP2x86`

## Q2: How many processes were running when the image was acquired?

- Mình dùng plugin `pslist` của Volatility 2 với profile đã xác định ở câu 1: `vol2 -f YBERDEF-567078-20230213-171333.raw --profile=WinXPSP2x86 pslist`. Plugin này liệt kê cả các tiến trình đã kết thúc nhưng cấu trúc vẫn còn trong bộ nhớ, nên mình chỉ tính các tiến trình **không có Exit time** , vì đó là các tiến trình còn đang chạy tại thời điểm thu thập.

<img width="1243" height="476" alt="image" src="https://github.com/user-attachments/assets/e01e82fa-9ef6-43f7-93f6-3f7de5a57af7" />

- Tổng là `25` tiến trình nhưng trừ cho `6` tiến trình đã kết thúc là còn `19`

**Đáp án:** `19`

## Q3: What is the process ID of cmd.exe?

- Dựa vào kết quả ở câu 2 thì mình tìm được ID của tiến trình `cmd.exe` là `1960`

## Q4: What is the name of the most suspicious process?

- Tiếp tục nhìn vào kết quả ở câu 2 mình phát hiện được một tiến trình rất đáng nghi ngờ có tên `rootkit.exe`

**Đáp án:** `rootkit.exe`

## Q5: Which process shows the highest likelihood of code injection?

- Mình dùng plugin `malfind` của Volatility 2 để tìm các vùng nhớ nghi ngờ code injection: `vol2 -f CYBERDEF-567078-20230213-171333.raw --profile=WinXPSP2x86 malfind`

- Kết quả cho thấy tiến trình **svchost.exe** (PID 880) có một vùng nhớ tại địa chỉ `0x980000` với quyền `PAGE_EXECUTE_READWRITE`, và bắt đầu bằng header `4d 5a` (`MZ`). Header này có trường trỏ tới PE header hợp lệ, cho thấy một file PE hoàn chỉnh đã bị nạp vào bộ nhớ của tiến trình.

<img width="742" height="155" alt="image" src="https://github.com/user-attachments/assets/e8ad661b-9d80-43a0-b7ef-ae95f182d522" />

**Đáp án:** `svchost.exe`

## Q6: There is an odd file referenced in the recent process. Provide the full path of that file.

- Tiến trình có khả năng bị inject nhất ở câu 5 là `svchost.exe` (PID 880), nên mình dùng plugin `handles` để liệt kê các file mà tiến trình này đang mở: `vol2 -f YBERDEF-567078-20230213-171333.raw --profile=WinXPSP2x86 handles -p 880 -t file`.

- Trong các handle trả về, mình thấy handle số `0x340` trỏ tới `\Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys`, tương ứng đường dẫn **C:\WINDOWS\system32\drivers\str.sys**. Đây là một file driver chế độ kernel mà tiến trình `svchost.exe` \ mở một cách bất thường , kết hợp với việc tiến trình này đã bị inject mã ở câu 5 nên mình xem đây là file bất thường.

<img width="1495" height="482" alt="image" src="https://github.com/user-attachments/assets/658ef732-5a6e-4b99-9bb5-7fc16ebed0a1" />

**Đáp án:** `C:\WINDOWS\system32\drivers\str.sys`

## Q7: What is the name of the injected DLL file loaded from the recent process?

- Với tiến trình `svchost.exe` (PID 880) ở câu 5, mình dùng plugin `ldrmodules` để so sánh các module trong ba danh sách `InLoad`, `InInit`, `InMem`: `vol2 -f CYBERDEF-567078-20230213-171333.raw --profile=WinXPSP3x86 ldrmodules -p 880`
- Mình lọc các dòng có `False` và thấy module **msxml3r.dll** tại địa chỉ `0x009a0000` có cả ba cột `InLoad`, `InInit`, `InMem` đều là `False`, đường dẫn ánh xạ là `\WINDOWS\system32\msxml3r.dll`. Module này không nằm trong danh sách module đã nạp của tiến trình, cho thấy nó được inject thay vì nạp theo cách thông thường.

<img width="977" height="457" alt="image" src="https://github.com/user-attachments/assets/0369c63b-9d98-4fed-843d-8ad0ce815c23" />

**Đáp án:** `msxml3r.dll`

## Q8: What is the base address of the injected DLL?

- Mình dùng lại kết quả plugin `malfind` của Volatility 2 cho tiến trình `svchost.exe` (PID 880): `vol2 -f CYBERDEF-567078-20230213-171333.raw --profile=WinXPSP2x86 malfind -p 880 `
- Kết quả có vùng nhớ tại địa chỉ **0x980000** với quyền `PAGE_EXECUTE_READWRITE`, là vùng cấp phát riêng và bắt đầu bằng header `MZ`, tức một file PE đã bị inject.

<img width="800" height="201" alt="image" src="https://github.com/user-attachments/assets/b9d2265d-3bb4-4d2c-a3fe-6169e3bffe52" />

**Đáp án:** `0x980000`
