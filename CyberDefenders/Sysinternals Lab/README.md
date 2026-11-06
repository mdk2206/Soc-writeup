# Sysinternals Lab
## 1. Bối cảnh

Bài Lab mô phỏng một sự cố trên máy trạm của người dùng. Người dùng tin rằng mình đang tải bộ công cụ SysInternals và cố mở nó, nhưng các công cụ không khởi chạy và không thể truy cập được. Kể từ đó, người dùng nhận thấy hệ thống chậm dần và phản hồi kém, gợi ý rằng thứ được tải về không phải bộ công cụ hợp pháp mà có thể đã kích hoạt hoạt động độc hại chạy ngầm trên máy.

Nhiệm vụ của mình là đóng vai chuyên gia điều tra số: phân tích các artifact được cung cấp để xác định file giả mạo mà người dùng đã tải, các tiến trình và hành vi độc hại phát sinh sau đó, nguyên nhân khiến hệ thống chậm, từ đó trích xuất các IOCs phục vụ việc truy vết và xử lý sự cố.

## 2. Điều tra

### Q1: What was the malicious executable file name that the user downloaded?
- Mình mở file ảnh đĩa `.E01` bằng FTK Imager để phân tích , mở rộng phân vùng Windows rồi vào thư mục `Users`. Vì kịch bản nói người dùng tải file về, mình kiểm tra các thư mục thường chứa file tải xuống hoặc file dùng chung, gồm `Downloads` của người dùng và `C:\Users\Public`.
- Tại đây mình phát hiện, ngoài file hệ thống `desktop.ini` thì còn có một file thực thi **SysInternals.exe** (57.344 byte, thời gian sửa đổi 11/15/2022 9:18:51). Đây là tên giả dạng bộ công cụ SysInternals, nhưng dung lượng chỉ khoảng 56 KB, quá nhỏ so với cả một bộ công cụ, và biểu tượng dấu X đỏ trong FTK Imager cho thấy file đã bị xóa khỏi hệ thống tệp.

<img width="1917" height="805" alt="image" src="https://github.com/user-attachments/assets/a7cc6354-c9de-4489-a960-5e8ccf67ad8b" />

- Dựa vào những dấu hiệu bất thường đó thì mình kết luận file thực thi đáng ngờ mà người dùng đã tải xuống là  `SysInternals.exe`

### Q2: When was the last time the malicious executable file was modified?

- Dựa vào kết quả của câu 1 thì FTK cũng đã cung cấp cho mình biết thời gian sửa file thực thi đó lần cuối cùng chính là `2022-11-15 21:18`

### Q3: What is the SHA1 hash value of the malware?

- Mình thử xem nội dung `SysInternals.exe` trong trình xem hex của FTK Imager thì thấy toàn byte `00`, nghĩa là nội dung file không khôi phục được (file đã bị xóa), nên không thể băm trực tiếp từ ảnh đĩa.
- Sau đó mình chuyển sang `Amcache.hve`, registry hive lưu siêu dữ liệu của các file thực thi đã chạy trên hệ thống để phân tích. Mình export file này từ `Windows\appcompat\Programs` rồi phân tích bằng AmcacheParser: ` .\AmcacheParser.exe -f "D:\Cyberdefender\Amcache.hve" --csv "D:\Cyberdefender" --csvf amcache.csv`

<img width="1453" height="622" alt="image" src="https://github.com/user-attachments/assets/c81c56ca-70c9-4f05-a830-72675621f3ce" />

- Mình mở `amcache_UnassociatedFileEntries.csv` bằng Timeline Explorer, tìm `SysInternals.exe` và thấy mục tương ứng có SHA1 là **fa1002b02fc5551e075ec44bb4ff9cc13d563dcf**.

<img width="1917" height="430" alt="image" src="https://github.com/user-attachments/assets/11f91ce6-257e-435c-8c7a-a18ee69b65aa" />

### Q4: Based on the Alibaba vendor, what is the malware's family?

- Mình lấy SHA1 của `SysInternals.exe` từ AmCache ở câu 3 và tra trên VirusTotal
- Trong tab Detection, vendor Alibaba nhận diện mẫu với nhãn `Downloader:Win32/Rozena.cadb0acb`

<img width="1917" height="582" alt="image" src="https://github.com/user-attachments/assets/09bfb71c-e61c-4c94-b0a7-8265df6b3adf" />

### Q5: What is the first mapped domain's Fully Qualified Domain Name (FQDN)?

- Mình tiếp tục sử dụng kết quả Virustotal từ câu 4, sau đó mình chuyển sang phần Relations để xem hai mục Contacted URLs và Contacted Domains.
- Tại đây mình phát hiện trong Contacted URLs, chỉ có `http://www.malware430.com/html/VMwareUpdate.exe` bị 3/92 engine gắn cờ độc hại, URL này tải một file thực thi giả dạng bản cập nhật VMware. FQDN của máy chủ là **www.malware430.com**.

<img width="1355" height="333" alt="image" src="https://github.com/user-attachments/assets/31fac0c6-9b0a-4aba-a5dd-7a8ca5afae44" />

### Q6: The mapped domain is linked to an IP address. What is that IP address?
- Vì domain được ánh xạ tới một IP, mình kiểm tra các nơi lưu ánh xạ thủ công trên máy nạn nhân. Trong FTK Imager, mình mở file `\Windows\System32\drivers\etc\hosts` và thấy được `192.168.15.10	www.malware430.com`


<img width="925" height="582" alt="image" src="https://github.com/user-attachments/assets/afa9c459-9050-4437-acff-3ff20044a3a6" />

Đáp án: `192.168.15.10`

### Q7: What is the name of the executable dropped by the first-stage executable?
- Mình xem tab Behavior của `SysInternals.exe` trên VirusTotal, phần Processes Created. Sau khi mẫu chạy, có lệnh `cmd.exe /C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto`, cho thấy mẫu thả file **vmtoolsIO.exe** vào `C:\Windows` rồi cài nó thành dịch vụ tự chạy.

<img width="1292" height="163" alt="image" src="https://github.com/user-attachments/assets/ae74b547-81dc-457d-80bb-886c54350384" />

### Q8: What is the name of the service installed by 2nd-stage executable?
- Từ dòng lệnh ở câu 7, file giai đoạn hai `vmtoolsIO.exe` được chạy với tham số `-install`, sau đó `net start` và `sc config ... start= auto` đều dùng tên **VMwareIOHelperService**. Như vậy dịch vụ được cài là VMwareIOHelperService, được đặt tự chạy cùng hệ thống và giả dạng dịch vụ của VMware Tools.

**Đáp án:** `VMwareIOHelperService`
