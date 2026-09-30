# Web Investigation Lab
## 1. Bối cảnh
Bạn là một chuyên gia phân tích an ninh mạng (SOC Analyst) làm việc tại BookWorld - một nền tảng nhà sách trực tuyến lớn. Vào một buổi tối muộn, hệ thống cảnh báo tự động của công ty bất ngờ bị kích hoạt.

Hệ thống ghi nhận một sự gia tăng đột biến và bất thường về số lượng truy vấn vào cơ sở dữ liệu, kèm theo mức sử dụng tài nguyên máy chủ tăng vọt. Sự bất thường này là dấu hiệu rõ ràng của một cuộc tấn công mạng, đe dọa trực tiếp đến tính toàn vẹn của hệ thống nội bộ cũng như nguy cơ rò rỉ dữ liệu khách hàng của BookWorld.

## Cách làm

### Câu 1: By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?

#### Cách làm 

- Mình sẽ vào Statistics -> Endpoints để tìm kiếm địa chỉ IP tạo ra nhiều lưu lượng truy cập bất thường nhất.

<img width="1097" height="322" alt="image" src="https://github.com/user-attachments/assets/4bea233d-b970-4cb6-9c8d-6066316a919f" />


#### Quan sát thấy:

- Trong bảng thống kê, có hai địa chỉ IP trao đổi một lượng gói tin khổng lồ và vượt trội hoàn toàn so với phần còn lại: 73.124.22.98 (88.740 gói tin) và 111.224.250.131 (88.484 gói tin). Các IP khác chỉ gửi vài trăm gói tin.
- Trong hai địa chỉ này, một IP đóng vai trò là máy chủ Web của BookWorld, và IP còn lại chính là máy của kẻ tấn công đang liên tục gửi các payload dò quét nên mình sẽ lọc các gói tin http để tìm xem source và destination.

- <img width="1917" height="432" alt="image" src="https://github.com/user-attachments/assets/43414588-d12e-4ed4-a193-47558e6550dc" />

#### Kết quả

- IP của kẻ tấn công là: 111.224.250.131

<img width="996" height="207" alt="image" src="https://github.com/user-attachments/assets/69a79b5d-ad2d-494d-a7a1-b2bc20d2c17f" />


### Câu 2: If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?

#### Cách làm: 

- Mình sẽ sao chép địa chỉ IP của kẻ tấn công (111.224.250.131) vừa xác định được ở Câu 1.Sau đó dán nền tảng tra cứu vị trí địa lý IP công cộng (Ở đây mình chọn dùng ipinfo.io )
- Mình quan sát thấy rằng IP này được phân bố từ Shijiazhuang, Trung Quốc.

 <img width="1165" height="662" alt="image" src="https://github.com/user-attachments/assets/73853ad6-09dc-488c-8147-9cf487aedeb5" />

 #### Kết luận 

 - Thành phố xuất phát của kẻ tấn công là: Shijiazhuang.




### Câu 3: Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable PHP script name?

#### Cách làm 

- Trên giao diện Wireshark, mình áp dụng bộ lọc http.request.method == "GET" && ip.src == 111.224.250.131 để thu hẹp phạm vi, chỉ hiển thị các yêu cầu HTTP GET được gửi từ IP của kẻ tấn công đến máy chủ web BookWorld.
- Nhận thấy rằng kẻ tấn công liên tục gửi hàng loạt các truy vấn chứa payload kiểm thử SQL Injection (như %27 - dấu nháy đơn, mệnh đề OR, AND) nhắm vào một tệp PHP duy nhất trên hệ thống.Tệp này nhận dữ liệu đầu vào thông qua tham số ?search=

<img width="1917" height="547" alt="image" src="https://github.com/user-attachments/assets/91cd9d79-872c-4739-b36d-982a0f5896d9" />

#### Kết luận: 

- Tên script PHP dễ bị tổn thương là: search.php

<img width="997" height="227" alt="image" src="https://github.com/user-attachments/assets/1f439ae7-22c8-4de8-a754-856fda590119" />

### Câu 4: Establishing the timeline of an attack, starting from the initial exploitation attempt, what is the complete request URI of the first SQLi attempt by the attacker?

#### Cách làm 

- Để tìm nỗ lực khai thác SQL Injection đầu tiên theo dòng thời gian, mình áp dụng bộ lọc trên Wireshark: http.request.method == "GET" && ip.src == 111.224.250.131 && http.request.uri contains "search.php"
- Mình sẽ bỏ qua các request bình thường (ví dụ chỉ có ?search=book) và tìm gói tin đầu tiên bắt đầu chứa các ký tự lạ hoặc có dấu % (dấu hiệu của việc chèn payload). 

 <img width="1917" height="1016" alt="image" src="https://github.com/user-attachments/assets/ea3fe622-a624-465b-ae48-22352a69d9e5" />

- Ở đây mình sẽ chọn gói 357 copy value url
- Sau khi copy url mình sẽ dán vào cyberchef để giải mã nó

<img width="1548" height="540" alt="image" src="https://github.com/user-attachments/assets/9114c09d-f4f4-4980-8130-0a371b15f802" />

#### Kết quả
- Sau khi giải mã url trên cyberchef thì mình nhận được kết quả là: /search.php?search=book and 1=1; -- -

<img width="1002" height="258" alt="image" src="https://github.com/user-attachments/assets/e5bf4169-b963-42b0-a21a-6ac4405e7d86" />

### Câu 5: Can you provide the complete request URI that was used to read the web server's available databases?

#### Cách làm

- Mình sẽ thiết lập bộ lọc trên Wireshark: http.request.method == "GET" && ip.src == 111.224.250.131 && http.request.uri contains "SCHEMATA". Vì trong SQL, nếu muốn biết máy chủ web có những cơ sở dữ liệu nào thì bắt buộc phải truy vấn vào bảng hệ thống mặc định của MySQL là INFORMATION_SCHEMA.SCHEMATA

 <img width="1917" height="1020" alt="image" src="https://github.com/user-attachments/assets/226219ca-17c8-4f94-ac64-2faee14e241d" />

- Sau đó mình cũng sẽ copy chuỗi url này và dán vào cyberchef để giải mã tương tự câu 4.

<img width="1532" height="525" alt="image" src="https://github.com/user-attachments/assets/07241c90-eeaa-47c4-b4f9-80102d2b3cfa" />

#### Kết luận 

- Request URI đầy đủ để đọc danh sách cơ sở dữ liệu là:
/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7171787671,JSON_ARRAYAGG(CONCAT_WS(0x7a7674716b6a,schema_name)),0x71717a6a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -

<img width="1003" height="232" alt="image" src="https://github.com/user-attachments/assets/1669a91f-549e-4cb6-bcc5-974e2073c27f" />

### Câu 6: Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?

#### Cách làm 

- Trên Wireshark, mình lọc các gói tin HTTP GET có chứa tham số TABLE_NAME và chọn Follow -> HTTP Stream để kiểm tra nội dung phản hồi từ máy chủ. Vì Sau khi kẻ tấn công có được tên cơ sở dữ liệu, bước tiếp theo thường là trích xuất danh sách các Tables. Kẻ tấn công sẽ truy vấn vào INFORMATION_SCHEMA.TABLES

- Mình quan sát thấy trong luồng dữ liệu HTTP, phần yêu cầu cho thấy kẻ tấn công sử dụng công cụ tự động SQLmap để chèn payload UNION-Based SQLi yêu cầu trích xuất bảng.
- Phần phản hồi HTTP 200 OK từ máy chủ đã vô tình để lộ dữ liệu cơ sở dữ liệu ngay trong mã HTML của trang web. Cụ thể, máy chủ đã trả về mảng dữ liệu ["admin", "books", "customers"]

<img width="1917" height="607" alt="image" src="https://github.com/user-attachments/assets/0c5601c5-2079-42ee-8c8a-aaf2918680df" />

#### Kết luận 

- Tên bảng chứa dữ liệu người dùng là: customers

<img width="1001" height="215" alt="image" src="https://github.com/user-attachments/assets/e2e51f94-7c9b-49bb-bb79-c7a174c84120" />

### Câu 7: The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide the name of the directory discovered by the attacker?

#### Cách làm 

- Mình sẽ áp dụng bộ lọc: http.request.method == "POST" && ip.src == 111.224.250.131.Bởi vì để đăng nhập vào một thư mục ẩn, kẻ tấn công bắt buộc phải gửi một biểu mẫu chứa Username/Password lên máy chủ. Động tác này sẽ dùng phương thức POST
- Mình thấy rằng toàn bộ các yêu cầu POST này đều được kẻ tấn công gửi thẳng đến đường dẫn http://bookworldstore.com/admin/login.php, http://bookworldstore.com/admin/login.php và sau đó là http://bookworldstore.com/admin/index.php, http://bookworldstore.com/admin/index.php

<img width="1306" height="268" alt="image" src="https://github.com/user-attachments/assets/787e3003-3d41-4ca2-bb33-38564923c5c2" />

#### Kết luận 

- Tên thư mục được kẻ tấn công phát hiện là: /admin/

<img width="1007" height="256" alt="image" src="https://github.com/user-attachments/assets/d27e7a32-22c2-4b46-8fbb-137b4a5c717a" />

### Câu 8: Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?

#### Cách làm 

- Mình sẽ tiếp tục tận dụng lại kết quả từ bộ lọc http.request.method == "POST" && ip.src == 111.224.250.131 ở Câu 7. 
- Kẻ tấn công thực hiện 4 nỗ lực đăng nhập khác nhau. Mình tập trung vào gói tin POST cuối cùng trong chuỗi này (gói số 88699) vì đây là lần đăng nhập thành công trước khi hệ thống chuyển hướng sang trang quản trị index.php
- Tiếp theo mình sẽ vào HTTP stream để làm rõ vấn đề và phát hiện ra user cũng như password mà kẻ tấn công đã đăng nhập thành công (%21 chính là dấu ! do quá trình mã hóa url )

<img width="1052" height="547" alt="image" src="https://github.com/user-attachments/assets/48935ebe-da7e-4204-b17b-76549d65d90a" />

#### Kết luận 

- Thông tin đăng nhập kẻ tấn công đã sử dụng là:admin/admin123!

<img width="985" height="198" alt="image" src="https://github.com/user-attachments/assets/cb614756-fff0-4170-ae52-abc91206a33b" />

### Câu 9:

#### Cách làm 

- Mình sẽ áp dụng bộ lọc Wireshark nhận biết file PHP được tải lên: http.request.method == "POST" && http.request.uri contains "/admin/index.php". Vì theo dòng sự kiện thì sau khi kẻ tấn công đăng nhập thành công vào /admin/index.php (ở Câu 8), hành động tiếp theo thường là tải lên một Webshell để chiếm quyền điều khiển máy chủ và thao tác tải tệp này bắt buộc phải sử dụng phương thức POST.

- Sau đó mình sẽ vào HTTP stream để xem file php nào đã được tải lên
- Ngay lập tức bắt được NVri2vhp.php

<img width="1132" height="525" alt="image" src="https://github.com/user-attachments/assets/ee173710-1b55-449f-a310-2a001ae384f5" />


#### Kết luận 

- Tên của tập lệnh độc hại được tải lên là:NVri2vhp.php

<img width="998" height="218" alt="image" src="https://github.com/user-attachments/assets/b7741074-5cb4-4195-9b53-365393fae97d" />



 

