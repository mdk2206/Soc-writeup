# HawkEye Lab
## 1. Bối cảnh 
Bài Lab mô phỏng một sự cố đánh cắp dữ liệu bằng keylogger HawkEye. Một kế toán trong tổ chức nhận được email về một hóa đơn kèm đường link tải xuống. Ngay sau khi mở email, đội giám sát ghi nhận lưu lượng mạng đáng ngờ phát sinh từ máy của người này.

Nhiệm vụ của mình là đóng vai chuyên viên SOC: phân tích bản bắt gói mạng bằng Wireshark và CyberChef để dựng lại diễn biến sự cố, xác định các IoCs, các nỗ lực rò rỉ dữ liệu và thông tin đăng nhập bị đánh cắp. Công cụ sử dụng trong bài: Wireshark, Brim, Apackets, MaxMind GeoIP, VirusTotal.

## 2. Điều tra

### Q1: How many packets does the capture have?

- Ở câu này mình sẽ dùng chức năng `Capture File Properties` của wireshark để đọc số lượng gói tin. Kết quả mình đọc được là có tổng `4003` gói tin.

<img width="1217" height="913" alt="image" src="https://github.com/user-attachments/assets/059cd4aa-0c4c-41b0-8a87-34265a6567bb" />

### Q2: At what time was the first packet captured (UTC)?

- Cũng tiếp tục từ kết quả của phần `Capture File Properties` ở câu 1, mình nhìn vào ` First packet: 2019-04-11 03:37:07 `, nhưng vì do đây đang hiển thị theo múi giờ của máy tính là `UTC+7` mà đề bài lại yêu cầu theo múi giờ UTC nên đáp án cuối cùng sẽ là `2019-04-10 20:37`

### Q3: What is the duration of the capture?

- Cũng từ kết quả ở phần `Capture File Properties` của câu 1 mình nhìn vào cột `Elapsed` nó có giá trị là `01:03:41`.

### Q4: What is the most active computer at the link level?

- Ở câu này mình sẽ điều hướng tới **Statistics → Endpoints → Ethernet** để tìm ra thiết bị truyền/nhận nhiều dữ liệu nhất. Kết quả cho thấy địa chỉ MAC đứng ở vị trí đầu tiên với tổng số gói tin lớn nhất (4,003 gói tin) là `00:08:02:1c:47:ae`.

<img width="756" height="251" alt="image" src="https://github.com/user-attachments/assets/61655761-b52d-4f5b-a81f-330ae58316fb" />

### Q5: Manufacturer of the NIC of the most active system at the link level?

- Ở câu 4 mình đã tìm được địa chỉ MAC là `00:08:02:1c:47:ae`. Sau đó mình tách 3 byte đầu tiên (OUI) là `00:08:02` để tra cứu mã OUI này trên cơ sở dữ liệu nhà sản xuất thiết bị mạng và xác định được tên nhà sản xuất card mạng là **Hewlett Packard**.

### Q6: Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?

- Từ kết quả thu được ở Q5, mình tiến hành tra cứu thông tin của NIC này thì biết được trụ sở chín của Hewlett-Packard / HP nằm tại thành phố **Palo Alto, bang California, Hoa Kỳ**

### Q7: The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture?

- Ở câu này mình sẽ truy cập menu **Statistics → Endpoints** và chọn tab **IPv4** để xem danh sách các địa chỉ mạng xuất hiện.
- Mình quan sát các địa chỉ IP thuộc phân đoạn `10.4.10.0/24`, và lọc được tổng cộng 4 địa chỉ xuất hiện trong bảng thống kê là : `10.4.10.2`, `10.4.10.4`, `10.4.10.132` và `10.4.10.255`. Trong đó `10.4.10.255` chính là địa chỉ Broadcast nên đáp án câu này sẽ là `3`.

<img width="1361" height="383" alt="image" src="https://github.com/user-attachments/assets/d630564c-4b8a-497b-965e-f3e331542899" />


### Q8: What is the name of the most active computer at the network level?

