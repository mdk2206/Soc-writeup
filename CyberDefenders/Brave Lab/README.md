# Brave Lab

## 1. Bối cảnh 

Bài Lab mô phỏng một sự cố trên máy trạm Windows nghi bị xâm nhập. Một ảnh bộ nhớ được thu thập từ máy này. Hệ thống của người dùng bị gắn cờ vì các hoạt động có thể độc hại, gồm các lần cố gắng truy cập trái phép và thói quen duyệt web bất thường. Đội an ninh cũng ghi nhận hoạt động mạng tới các địa chỉ IP bên ngoài gắn với các dịch vụ liên lạc được mã hóa.

Nhiệm vụ của mình là đóng vai chuyên viên SOC: phân tích memory dump bằng Volatility 3 để tìm hiểu các tiến trình liên quan, xác định các kết nối đang hoạt động tại thời điểm bị xâm nhập và lần theo cách sử dụng của các ứng dụng cụ thể, từ đó dựng lại hoạt động của người dùng. Công cụ sử dụng trong bài: Volatility 3, CertUtil, HxD.

## 2. Điều tra

### Q1: What time was the RAM image acquired according to the suspect system?

- Mình sẽ sử dụng Volatility 3 với plugin `windows.info` để phân tích thông tin siêu dữ liệu hạt nhân của tệp ảnh bộ nhớ RAM ` vol -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.info`

<img width="1465" height="487" alt="image" src="https://github.com/user-attachments/assets/ca704ce1-d79e-4ba0-ae84-fd8753f0ae21" />

- Tại trường `SystemTime` trong bảng kết quả mình xác định thời điểm bản dump RAM được thu thập là `2021-04-30 17:52`.

### Q2: What is the SHA256 hash value of the RAM image?

- Mình thực thi lệnh `Get-FileHash .\20210430-Win10Home-20H2-64bit-memdump.mem -Algorithm SHA256` để tính toán giá trị băm SHA-256 phục vụ xác minh tính toàn vẹn bằng chứng số, thu được chuỗi mã băm `9DB01B1E7B19A3B2113BFB65E860FFFD7A1630BDF2B18613D206EBF2AA0EA172`.

<img width="1452" height="188" alt="image" src="https://github.com/user-attachments/assets/b135c450-8c9c-4e42-abd8-eb64a54a12c4" />

### Q3: What is the process ID of brave.exe?

- Mình sử dụng Volatility 3 với plugin `windows.pstree` trên tệp ảnh bộ nhớ `20210430-Win10Home-20H2-64bit-memdump.mem` và lọc theo tiến trình `brave.exe`: `vol -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.pstree | grep "brave.exe"`

<img width="1457" height="106" alt="image" src="https://github.com/user-attachments/assets/9adc8f65-e1a6-4bcc-b125-08a92223cbc2" />

- Kết quả bản ghi tiến trình `\Device\HarddiskVolume2\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe` (có `PPID` là `1872`, khởi chạy lúc `2021-04-30 17:48:45 UTC`), mã định danh tiến trình (PID) của `brave.exe` là `4856`.

### Q4: How many established network connections were there at the time of acquisition?

- Ở câu này mình sẽ sử dụng plugin `windows.netscan` trên tệp ảnh bộ nhớ `20210430-Win10Home-20H2-64bit-memdump.mem`, lọc các phiên giao tiếp có trạng thái `ESTABLISHED`: ` (vol -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.netscan | Select-String "ESTABLISHED").Count`.
  

<img width="1547" height="86" alt="image" src="https://github.com/user-attachments/assets/d0b85cef-dca1-4516-82eb-d20607582f97" />


- Kết quả cho ra có `10` bản ghi kết nối mạng ở trạng thái `ESTABLISHED`.

### Q5: Which domain name does Chrome have an established network connection with?

- Ở câu này mình sử dụng plugin `windows.netscan` và lọc theo tiến trình chrome bằng lệnh `vol -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.netscan | Select-String "chrome.exe"`.

<img width="1793" height="418" alt="image" src="https://github.com/user-attachments/assets/71320e68-a95a-4d27-b6ce-6ca66ee9e42a" />

- Loại bỏ các phiên đã chuyển sang trạng thái chờ đóng (`FIN_WAIT2`, `CLOSE_WAIT`) và lưu lượng mDNS nội bộ trên cổng UDP `5353`, mình chỉ ghi nhận tiến trình `chrome.exe` (PID `1840`, offset `0xbf0f6c7104d0`) duy trì duy nhất một kết nối TCP trạng thái `ESTABLISHED` từ `10.0.2.15:49778` tới địa chỉ IP đích `185.70.41.130:443`.

- Sau đó mình thực hiện phân giải ngược DNS bằng lệnh `nslookup 185.70.41.130` thu được bản ghi PTR `185-70-41-130.protonmail.ch`, qua đó xác định tên miền gốc mà Chrome đang thiết lập kết nối tới là `protonmail.ch`.

### Q6: What is the MD5 hash value of the process executable for PID 6988?

- Mình sử dụng plugin `windows.pslist` kết hợp tham số `--pid 6988 --dump`: `vol -o . -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.pslist --pid 6988 --dump`, xác định tiến trình là `OneDrive.exe` và trích xuất tệp thực thi ra đĩa dưới tên `6988.OneDrive.exe.0x1c0000.dmp`.

<img width="1870" height="195" alt="image" src="https://github.com/user-attachments/assets/af976ead-97a1-4398-a5a5-d3a361ccda94" />

- Sau đó mình tính toán giá trị băm MD5 của tệp vừa trích xuất bằng lệnh `Get-FileHash .\6988.OneDrive.exe.0x1c0000.dmp -Algorithm MD5` thu được chuỗi MD5 là `0B493D8E26F03CCD2060E0BE85F430AF`.

<img width="1496" height="152" alt="image" src="https://github.com/user-attachments/assets/227d8759-9b44-4be2-9a39-fad4add762cb" />

### Q7: Can you identify the word that begins at offset 0x45BE876 and is 6 bytes long?

- Mình mở trực tiếp tệp ảnh bộ nhớ `20210430-Win10Home-20H2-64bit-memdump.mem` bằng trình biên tập thập lục phân HxD.

<img width="1002" height="680" alt="image" src="https://github.com/user-attachments/assets/d6d219db-5eca-4b0f-9524-c4f9c2d0bba2" />


- Sau đó mình tìm kiếm 6 byte liên tiếp bắt đầu từ offset `0x45BE876` (`68 61 63 6B 65 72`) theo yêu cầu của đề bài, tại cột giải mã văn bản thu được từ khóa là `hacker`.

### Q8: What is the creation date and time of the parent process of powershell.exe?

- Đầu tiên mình sử dụng plugin `windows.pslist`: `vol -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.pslist | Select-String -Pattern "PID|powershell"`, xác định được tiến trình `powershell.exe` (PID `5096`) được khởi tạo từ tiến trình cha mang `PPID` là `4352`.

<img width="1617" height="112" alt="image" src="https://github.com/user-attachments/assets/0ed75332-02b4-46a0-9a5d-cb0912e93c3d" />

- Sau đó mình tiếp tục truy vấn thông tin tiến trình có PID `4352` bằng lệnh `vol -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.pslist --pid 4352`, xác định tiến trình cha là `explorer.exe` với thời điểm khởi tạo (`CreateTime`) là `2021-04-30 17:39:48`.

<img width="1675" height="192" alt="image" src="https://github.com/user-attachments/assets/2303b418-bdc4-4cf4-adf0-5e3efff82681" />

### Q9: What is the full path and name of the last file opened in notepad?

- Ở câu này mình sử dụng plugin `windows.cmdline: vol -q -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.cmdline | Select-String -Pattern "notepad"`, mình ghi nhận tiến trình `notepad.exe` (PID `2520`) được khởi chạy kèm tham số đường dẫn rút gọn là `C:\Users\JOHNDO~1\AppData\Local\Temp\7zO4FB31F24\accountNum`.

<img width="1651" height="283" alt="image" src="https://github.com/user-attachments/assets/0e943697-e4fb-4595-9656-fc5c44c85765" />

### Q10: How long did the suspect use Brave browser? (In Hours)

- Mình sử dụng plugin `windows.registry.userassist :vol -q -f .\20210430-Win10Home-20H2-64bit-memdump.mem windows.registry.userassist | Select-String -Pattern "Time Focused|brave"` để phân tích dữ liệu khóa Registry `UserAssist`

<img width="1917" height="567" alt="image" src="https://github.com/user-attachments/assets/0bc61cbe-d88d-4eb3-bda5-237b9beafe82" />

- Mình kiểm tra bản ghi `Brave` thuộc nhánh `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`, ghi nhận `Count` = `9`, `Focus Count` = `22` và tổng thời gian tương tác (`Time Focused`) là `4:01:54.328000`, tương đương `4` giờ.
