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




