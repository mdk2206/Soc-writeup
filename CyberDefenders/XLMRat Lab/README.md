# XLMRat Lab

## 1. Bối cảnh
Một máy đã bị xâm nhập và được đánh dấu do có lưu lượng mạng đáng ngờ. Nhiệm vụ là phân tích tệp PCAP để xác định phương thức tấn công, xác định các phần mềm độc hại và truy vết dòng thời gian của các sự kiện. Cần tập trung vào cách kẻ tấn công truy cập, các công cụ hoặc kỹ thuật được sử dụng, và cách phần mềm độc hại hoạt động sau khi bị xâm nhập.

## 2. Quá trình điều tra

### Câu 1: The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?

#### Cách làm:
- Mình sử dụng bộ lọc http.request trên Wireshark, mình thấy có 2 yêu cầu GET gửi tới IP 45.126.209.4 qua cổng 222: tải xlm.txt (Frame 4) và tải mdm.jpg (Frame 12).

- Để xác định đâu là mã độc chính, mình vào TCP Stream để phân tích mã nguồn thực sự bên trong.

<img width="1912" height="535" alt="image" src="https://github.com/user-attachments/assets/1dd943d3-17f3-4e07-9b02-0a2c14390b37" />


<img width="1792" height="826" alt="image" src="https://github.com/user-attachments/assets/fc1c9157-e930-4a83-8107-22e93aa41aba" />

<img width="1905" height="885" alt="image" src="https://github.com/user-attachments/assets/8d58bd4c-7e0a-4551-be2f-0b4a855bf460" />

#### Quan sát thấy:
- Với tệp xlm.txt: Nội dung trả về chỉ là một đoạn VBScript được làm rối để ghép thành một lệnh nào đó 

- Còn với tệp mdm.jpg: Tệp này hoàn toàn không phải là ảnh. Nội dung thực chất là một script PowerShell lớn chứa biến $hexString_bbb = "4D_5A_90_00_..."(chữ MZ) chính là Magic Bytes đặc trưng của các file thực thi trên Windows (PE file như .exe, .dll).

#### Kết luận:
- URL mà giai đoạn phần mềm độc hại đầu tiên được cài đặt là: http://45.126.209.4:222/mdm.jpg

<img width="1013" height="195" alt="image" src="https://github.com/user-attachments/assets/36cc320c-8594-45fe-b946-c83f312d4d4e" />

### Câu 2: Which hosting provider owns the associated IP address?

#### Cách làm:

- Mình sử dụng virustotal để tra cứu thông tin.

#### Quan sát thấy.

- Tại mục Basic Properties, dòng Autonomous System Label ghi rõ thông tin tổ chức quản lý dải mạng này là ReliableSite.Net LLC.

<img width="938" height="225" alt="image" src="https://github.com/user-attachments/assets/72ac91e0-0deb-4e08-8aa4-5554c781de64" />


#### Kết luận 

- Nhà cung cấp hosting sở hữu địa chỉ IP liên quan là reliablesite.net.

<img width="997" height="180" alt="image" src="https://github.com/user-attachments/assets/5377848f-5263-417b-8299-facc422dcfe4" />

### Câu 3: By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?

#### Cách làm 

- Dựa vào nội dung script của file mdm.jpg đã phân tích ở Câu 1, mình xác định được payload thực thi nhị phân (PE file) được lưu dưới dạng chuỗi hex trong biến $hexString_bbb. Chuỗi này bắt đầu bằng 4D_5A (Magic bytes MZ của file thực thi trên Windows)
- Mình copy toàn bộ giá trị của chuỗi hex này và đưa vào công cụ CyberChef để giải mã và trích xuất mã băm.
- Trong CyberChef, mình thiết lập Recipe gồm các bước sau: Find / Replace (để loại bỏ dấu "-" , From Hex, SHA2(256)).

<img width="1535" height="600" alt="image" src="https://github.com/user-attachments/assets/fedfafb8-049f-4302-a3ba-07cb8b61a1e2" />

#### Kết luận:

- SHA256 của tệp thực thi phần mềm độc hại là: 1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798

<img width="992" height="195" alt="image" src="https://github.com/user-attachments/assets/7e6fc6a6-4210-43bc-8153-e26990fca58b" />

### Câu 4: What is the malware family label based on Alibaba?

#### Cách làm 

- Mình sẽ sử dụng mã băm SHA256 của tệp thực thi mã độc vừa tìm được ở Câu 3 và tra cứu trên virustotal
- Ở phần Detection, mình sẽ tìm đến security vendors để tìm engine quét của Alibaba.

<img width="1675" height="80" alt="image" src="https://github.com/user-attachments/assets/3a656300-3ed1-4d2e-a951-67d0cbb986db" />

#### Quan sát thấy:
- Trong danh sách trả về, hãng bảo mật Alibaba đã nhận diện và gắn nhãn họ mã độc cho tệp này là AsyncRAT.
#### Kết luận 
- Nhãn họ phần mềm độc hại dựa trên Alibaba là: AsyncRAT

<img width="1016" height="178" alt="image" src="https://github.com/user-attachments/assets/d617b352-b947-4b69-a1a4-0fbe57c7d06e" />

### Câu 5: What is the PE header compile (Creation Time) timestamp of the malware?

#### Cách làm 

- Mình tiếp tục sử dụng kết quả tra cứu mã băm SHA256 ban nảy trên nền tảng VirusTotal, tìm kiếm đến trường thông tin Creation Time và thấy được: 
2023-10-30 15:08:44 UTC

<img width="633" height="165" alt="image" src="https://github.com/user-attachments/assets/51b50644-00cb-4cf3-aa13-295525ba098b" />

#### Kết luận 

- Thời gian biên dịch tiêu đề PE (Thời gian tạo) của phần mềm độc hại là: 2023-10-30 15:08

<img width="998" height="178" alt="image" src="https://github.com/user-attachments/assets/0894392a-eef2-451d-b5f9-a1fecf61e204" />

### Câu 6: Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.

#### Cách làm 
- Mình sẽ phân tích đoạn mã nguồn PowerShell vừa được trích xuất từ tệp mdm.jpg và tìm kiếm các biến làm nhiệm vụ khai báo đường dẫn hệ thống để chuẩn bị khởi tạo tiến trình mới.
#### Quan sát thấy:

- Trong đoạn script, kẻ tấn công sử dụng kỹ thuật làm rối để ẩn giấu đường dẫn thực thi, tránh bị các phần mềm diệt virus phát hiện. Chúng chèn hàng loạt ký tự # vào biến $NA và chuỗi của biến $AC.

<img width="872" height="43" alt="image" src="https://github.com/user-attachments/assets/b81bd84f-5cb6-4632-b9f6-d9de7d32e76c" />

- Lệnh -replace '#', '' sẽ tự động tìm và xóa bỏ toàn bộ các dấu # khi đoạn script này chạy.


#### Kết quả
- Sau khi gỡ rối thì mình đã tìm được LOLBin được sử dụng để thực thi tiến trình bí mật trong script này là: C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe

<img width="1017" height="186" alt="image" src="https://github.com/user-attachments/assets/94e6e41b-29b9-48ae-bf20-b4c0b3071556" />

### Câu 7: The script is designed to drop several files. List the names of the files dropped by the script.


#### Cách làm.

- Mình tiếp tục phân tích đoạn mã nguồn PowerShell và thấy rằng kẻ tấn công sử dụng liên tiếp 3 lệnh [IO.File]::WriteAllText để ghi các khối dữ liệu (được gán trong biến $Content) xuống ổ cứng của nạn nhân đó là: Conted.ps1, Conted.bat và Conted.vbs

 <img width="995" height="752" alt="image" src="https://github.com/user-attachments/assets/b4dbe71c-1c23-476f-b4fe-c99b08316b78" />

 <img width="741" height="252" alt="image" src="https://github.com/user-attachments/assets/86674684-4471-4748-b250-06813092fde4" />



- #### Kết luận:
- Tên các tệp được script thả ra là: Conted.ps1, Conted.bat, Conted.vbs.

- <img width="1013" height="182" alt="image" src="https://github.com/user-attachments/assets/f39e4eb3-0f29-4b4f-8b39-5e6040aa575f" />
