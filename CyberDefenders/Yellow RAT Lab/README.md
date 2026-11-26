# Yellow RAT Lab
## 1. Bôi cảnh 

Bài Lab mô phỏng một sự cố tại GlobalTech Industries. Trong một đợt kiểm tra an ninh IT định kỳ, đội ngũ phát hiện lưu lượng mạng bất thường phát sinh từ nhiều máy trạm. Qua điều tra ban đầu, họ nhận thấy các truy vấn tìm kiếm của một số nhân viên bị chuyển hướng tới những website lạ. Phát hiện này làm dấy lên lo ngại về một vụ xâm nhập và dẫn đến yêu cầu điều tra kỹ hơn.

Nhiệm vụ của mình là đóng vai chuyên viên threat intelligence: phân tích các artifact mã độc bằng các nền tảng tình báo như VirusTotal để xác định các chỉ số xâm phạm (IOCs), máy chủ chỉ huy và điều khiển (C2), từ đó hiểu chiến thuật của đối phương và thu thập càng nhiều thông tin về sự cố càng tốt. Công cụ sử dụng trong bài: VirusTotal, Red Canary.

## 2. Điều tra

### Q1: What name does Red Canary use for the threat cluster associated with the SHA256 in hash.txt? Submit the name used in its technical analysis, without adding a malware-type suffix.

- Mình mở tệp `hash.txt` và lấy mã băm SHA-256 của mẫu mã độc đưa lên VirusTotal để phân tích.

- Kết quả ghi nhận 57/71 công cụ bảo mật phát hiện với nhãn phổ biến là `trojan.msil/polazert` (thuộc họ mã độc `polazert` / *Jupyter* / *SolarMarker*).

<img width="1916" height="897" alt="image" src="https://github.com/user-attachments/assets/ebf9e85b-925e-4c35-b3b6-54b40e7acb7d" />

- Sau đó mình đối chiếu thông tin tham chiếu tại thẻ COMMUNITY cùng các bài phân tích kỹ thuật của `Red Canary`, xác nhận tên cụm hoạt động đe dọa được sử dụng (không kèm hậu tố loại mã độc `RAT`) là `Yellow Cockatoo`.

### Q2: As part of our incident response, knowing the malware's common filenames can help us scan other workstations for potential infection. What is the common filename associated with this malware? (Use VirusTotal)

- Mình quan sát tên tệp đại diện hiển thị ngay bên dưới chuỗi mã băm ở phần đầu báo cáo và kiểm tra đối chiếu tại mục Names trong thẻ DETAILS, ghi nhận tên tệp phổ biến của mẫu DLL độc hại này là `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`.

<img width="515" height="97" alt="image" src="https://github.com/user-attachments/assets/264e003b-9d98-45d9-b63d-64ad8578e6f5" />

### Q3: Determining a malware sample's compilation timestamp can reveal insights into its development and deployment timeline. What compilation timestamp does VirusTotal show for this malware sample?

- Cũng trong kết quả điều tra được trên VirusTotal, mình ghi nhận tại trường `Creation Time` có giá trị là `2020-09-24 18:26`

<img width="700" height="211" alt="image" src="https://github.com/user-attachments/assets/f6716a7c-0476-46bc-8750-97d40b9a948f" />

### Q4: Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?

- Cũng từ kết quả ở Q3 mình ghi nhận được dòng `First Submission` có giá trị là `2020-10-15 02:47:37 UTC`.

### Q5: To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the .dat file that the malware dropped in the AppData folder?

- Mình điều tra sang nguồn tình báo mối đe dọa của Red Canary đối với Yellow Cockatoo thông qua báo cáo `Threat Detection Report ` và bài phân tích kỹ thuật gốc năm 2020. Mình phát hiện được sau khi payload .NET được nạp trực tiếp lên bộ nhớ, mã độc tạo một tệp lưu trữ cấu hình và mã định danh máy nạn nhân tại đường dẫn `%USERPROFILE%\AppData\Roaming\solarmarker.dat`.

### Q6: It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?

- Tại mục `Network Communication` trên VirusTotal , mình loại trừ các truy vấn chứng chỉ số và dịch vụ hợp lệ của Windows (`crt.sectigo.com`, `akamai.net`, `msn.com`, `msedge.net`). Sau đó mình kiểm tra hai mục `Memory Pattern Domains` và `Memory Pattern Urls`, ghi nhận địa chỉ máy chủ điều khiển được trích xuất từ vùng nhớ tiến trình là `gogohid.com` (`https://gogohid.com`).

<img width="341" height="207" alt="image" src="https://github.com/user-attachments/assets/df2cf695-40dc-4f73-951c-70d1e79d202f" />
