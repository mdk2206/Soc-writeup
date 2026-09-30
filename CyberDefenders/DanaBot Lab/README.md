# DanaBot Lab - CyberDefenders


## 1. Bối cảnh 

SOC phát hiện hoạt động đáng ngờ trong lưu lượng mạng: một máy đã bị xâm nhập và dữ liệu nhạy cảm của công ty bị đánh cắp. Nhiệm vụ là dùng file PCAP và Threat Intelligence để xác định sự cố xảy ra như thế nào.

## 2. Quá trình điều tra

### Câu 1: Which IP address was used by the attacker during the initial access?

#### Cách làm:

- Đầu tiên mình lọc bằng http.request để liệt kê các yêu cầu HTTP.

<img width="1917" height="993" alt="image" src="https://github.com/user-attachments/assets/7ccdca03-c2f1-442a-9612-70dd59f55303" />

- Mình sẽ loại các yêu cầu nền bình thường như: SSDP M-SEARCH tới 239.255.255.250 (Windows dò thiết bị LAN), /connecttest.txt (Windows kiểm tra kết nối), và yêu cầu OCSP kiểm tra chứng chỉ.
Sau đó mình thấy còn lại hai đích đáng nghi là: GET /login.php (frame 6) và GET /resources.dll (frame 250). Yêu cầu đầu tiên là frame 6 tại t = 0,34 s.
- Tiếp theo mình TCP Stream để xem nội dung trao đổi.

<img width="1905" height="831" alt="image" src="https://github.com/user-attachments/assets/22a385d2-172e-46b4-a086-ecca81e3ae53" />

#### Quan sát thấy 

- IP 10.2.14.101 gửi GET /login.php tới host portfolio.serveirc.com (IP 62.173.142.148).
- Máy chủ (nginx/1.14.0) trả 200 OK với Content-Type: application/octet-stream và Content-disposition: attachment, tức là đã ép trình duyệt tải một file về.
- User-Agent cho thấy nạn nhân dùng Microsoft Edge 121 trên Windows, ngôn ngữ trình duyệt it-IT.
- Header Date của máy chủ: 14/02/2024 16:25:54 GMT.
- Phần thân phản hồi là JavaScript bị làm rối.

#### Kết luận:
- Dựa vào những gì quan sát ở trên mình kết luận rằng: IP kẻ tấn công ở giai đoạn initial access là 62.173.142.148.

<img width="1010" height="181" alt="image" src="https://github.com/user-attachments/assets/c412bcb3-e37d-4ccd-9952-a0979b6990ca" />

### Câu 2: What is the name of the malicious file used for initial access?

#### Cách làm 

- Dựa vào TCP Stream của frame 6 ở câu 1, mình thấy dòng Content-disposition trong phản hồi của máy chủ xuất hiện file có tên là allegato_708.js
- 
#### Kết luận 
- File độc hại dùng cho initial access là allegato_708.js

<img width="1000" height="180" alt="image" src="https://github.com/user-attachments/assets/bc5cbd16-9259-4dea-8bfa-c4d0051dcf71" />


### Câu 3: What is the SHA-256 hash of the malicious file used for initial access?

#### Cách làm:
- Mình vào File → Export Objects → HTTP, chọn file tải từ portfolio.serveirc.com và lưu ra máy ảo .
- Sau đó tính SHA-256 bằng PowerShell:

<img width="803" height="132" alt="image" src="https://github.com/user-attachments/assets/db40df39-f366-4721-a627-ca5fc73d3c69" />

#### Kết luận:
- SHA-256 của file độc hại dùng cho initial access là `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`.

<img width="1002" height="177" alt="image" src="https://github.com/user-attachments/assets/ec3a625c-96f7-47d9-b5d0-97f498222318" />


### Câu 4: Which process was used to execute the malicious file?

#### Cách làm:
- Trong đoạn script mình thấy các đối tượng ActiveXObject và WScript, cho thấy script chạy dưới Windows Script Host.
- Mình tra hash SHA-256 trên VirusTotal, mở Behavior để xem process tree.

<img width="962" height="307" alt="image" src="https://github.com/user-attachments/assets/588a1462-aa04-43c6-96f3-c5a54e15a98b" />


#### Quan sát thấy
- Process tree cho thấy file allegato_708.js được mở bởi: WScript.exe


#### Kết luận:
Tiến trình thực thi file độc hại là WScript.exe.

<img width="997" height="183" alt="image" src="https://github.com/user-attachments/assets/4eface61-b592-40af-9f6d-09df66713a9e" />

### Câu hỏi 5: What is the file extension of the second malicious file utilized by the attacker?

#### Cách làm:
- Mình dùng lại danh sách http.request ở Q1. Sau khi loại các yêu cầu nền và yêu cầu login.php (đã dùng cho initial access), chỉ còn một yêu cầu đáng nghi.

<img width="1917" height="540" alt="image" src="https://github.com/user-attachments/assets/f3f60e0b-0d82-4e0c-8161-82318911df17" />


#### Quan sát thấy
- Frame 250 (t = 61,83 s, sau yêu cầu đầu khoảng 61 giây): 10.2.14.101 gửi GET /resources.dll tới 188.114.97.3(host soundata.top)
- Yêu cầu này đến sau khi script chạy, tới host khác với nơi phát script.

#### Kết luận:
Đuôi file của file độc hại thứ hai là .dll.

<img width="1000" height="180" alt="image" src="https://github.com/user-attachments/assets/0ea39cc4-b4c0-47e0-a0c6-165bf6e02578" />

### Câu hỏi 6: What is the MD5 hash of the second malicious file?

#### Cách làm:
- Mình vào Export Objects → HTTP, chọn file tải từ soundata.top và lưu lại.
- Sau đó tính MD5 bằng PowerShell:

<img width="837" height="142" alt="image" src="https://github.com/user-attachments/assets/326f740c-ef7d-4d10-a1cc-f3cc3a422086" />

#### Quan sát thấy
- MD5:=E758E07113016ACA55D9EDA2B0FFEEBE

#### Kết luận:
MD5 của file độc hại thứ hai resources.dll là E758E07113016ACA55D9EDA2B0FFEEBE











