# Ramnit Lab

## Bối cảnh 

Bài Lab mô phỏng một sự cố trên máy trạm của doanh nghiệp. Hệ thống phát hiện xâm nhập (IDS) cảnh báo hành vi đáng ngờ trên máy này, cho thấy khả năng cao đã bị mã độc xâm nhập. Đội an ninh thu thập một bản memory dump của máy để phục vụ điều tra.

Nhiệm vụ của mình là đóng vai chuyên gia phân tích: dùng Volatility để phân tích memory dump, xác định tiến trình độc hại, kết nối mạng và các dấu hiệu bất thường, từ đó truy vết hành động của mã độc, trích xuất các IOCs và báo cáo các phát hiện chính.

## Q1: What is the name of the process responsible for the suspicious activity?

- Mình dùng plugin `pstree` của Volatility để liệt kê cây tiến trình trong memory dump.
- Mình thấy tiến trình **ChromeSetup.exe** (PID 4628, tiến trình cha PID 4568) chạy từ `C:\Users\alex\Downloads\ChromeSetup.exe`. Tên giả dạng trình cài đặt Chrome và nằm trong thư mục Downloads của người dùng, không phải đường dẫn cài đặt chính thức, nên đây là tiến trình đáng ngờ. Cột tên trong `pstree` bị cắt thành `ChromeSetup.ex`, tên đầy đủ lấy từ đường dẫn thực thi.

<img width="1680" height="262" alt="image" src="https://github.com/user-attachments/assets/41939074-55e3-4371-9384-1facb3ed9fb2" />

**Đáp án:** `ChromeSetup.exe`

## Q2: What is the exact path of the executable for the malicious process?

- Mình dùng lại kết quả plugin `pstree` ở câu 1 cho tiến trình đáng ngờ `ChromeSetup.exe` (PID 4628). Cột đường dẫn thực thi cho thấy file nằm tại `\Device\HarddiskVolume3\Users\alex\Downloads\ChromeSetup.exe`, tương ứng đường dẫn **C:\Users\alex\Downloads\ChromeSetup.exe**.

**Đáp án:** `C:\Users\alex\Downloads\ChromeSetup.exe`

## Q3: Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?

- Để xem kết nối mạng của tiến trình đáng ngờ `ChromeSetup.exe` (PID 4628), mình dùng plugin `windows.netstat` của Volatility 3: `vol3 -f memory.dmp windows.netstat | grep "4628"`.

- Kết quả cho thấy tiến trình này có một kết nối TCP từ máy nạn nhân `192.168.19.133:49682` tới **58.64.204.181:5202** ở trạng thái `SYN_SENT`. Trạng thái `SYN_SENT` cho thấy mã độc đã cố kết nối tới địa chỉ này nhưng chưa thiết lập được kết nối.

**Đáp án:** `58.64.204.181`

## Q4: To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?

- Từ câu 3, mình có địa chỉ IP mà mã độc cố kết nối là `58.64.204.181`. Mình tra cứu địa chỉ này trên IP2Location.

- Kết quả cho thấy IP được gán cho thành phố **Hong Kong**

<img width="867" height="288" alt="image" src="https://github.com/user-attachments/assets/7155401c-105f-429d-a037-c1d22366809b" />


## Q5: Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?

- Mình dùng plugin `windows.dumpfiles` của Volatility 3 để trích các file mà tiến trình `ChromeSetup.exe` (PID 4628) đã mở trong bộ nhớ: `vol3 -f memory.dmp -o dump_pid/ windows.dumpfiles --pid 4628`.
- Trong kết quả, mình chọn file ảnh thực thi `file.0xca82b85325a0.....ImageSectionObject.ChromeSetup.exe.img`, ứng với địa chỉ `0xca82b85325a0`
- Mình tính SHA1 của file này bằng `sha1sum` và thu được **280c9d36039f9432433893dee6126d72b9112ad2**.

<img width="1082" height="147" alt="image" src="https://github.com/user-attachments/assets/831ac7a6-16c8-49d0-b105-3465d881ad88" />

## Q6: Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?

- Mình tra SHA1 của file thực thi đã trích ở câu 5 (`280c9d36039f9432433893dee6126d72b9112ad2`) trên VirusTotal.
- Ở tab Details, mục History cho thấy Creation Time là **2019-12-01 08:36:04 UTC**

**Đáp án:** `2019-12-01 08:36`

## Q7: Identifying the domains associated with this malware is crucial for blocking future malicious communications and detecting any ongoing interactions with those domains within our network. Can you provide the domain connected to the malware?

- Mình tiếp tục dùng kết quả tra cứu trên Virustotal ở câu 6, ở mục Contacted Domains mình thấy được 4 domain, trong đó `dnsnb8.net` (13/92 detections) và `ddos.dnsnb8.net` (15/92 detections), bị nhiều engine gắn cờ độc hại. Hai domain còn lại là `www.microsoft.com` và một domain thuộc hạ tầng Microsoft, đều 0/92 detections nên mình loại.
- Theo cấu trúc của đề bài nên mình sẽ lựa chọn đáp án là `dnsnb8.net`
