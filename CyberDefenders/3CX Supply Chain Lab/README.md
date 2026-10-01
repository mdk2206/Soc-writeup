# 3CX Supply Chain Lab

## 1. Bối cảnh 

Đây là mô phỏng một vụ tấn công chuỗi cung ứng (supply chain): phần mềm gọi điện 3CX bị cài mã độc ngay trong bản cập nhật chính thức, nên máy nạn nhân chạy mã độc trong một ứng dụng "đáng tin". Nhiệm vụ của bạn là dựng lại cách tấn công, xác định kỹ thuật (TTP) và quy cho một nhóm tấn công.

## 2. Điều tra 

### Câu 1: nderstanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial for making informed decisions if these compromised versions are present in the organization. How many versions of 3CX running on Windows have been flagged as malware?

#### Cách làm.
- Mình tra cứu thông tin trên các trang uy tín thì tìm ra được có 2 phiên bản trên windows bị ảnh hưởng đó là 18.12.407 và 18.12.416.

<img width="1193" height="403" alt="image" src="https://github.com/user-attachments/assets/6760005c-ff04-42ac-94c8-8690c4285a6c" />

#### Kết luận 

- Có 2 phiên bản 3CX trên Windows bị gắn cờ là mã độc.

<img width="983" height="217" alt="image" src="https://github.com/user-attachments/assets/e8680fb3-ddec-4deb-b4a7-b07e52ce2304" />


### Câu 2: Determining the age of the malware can help assess the extent of the compromise and track the evolution of malware families and variants. What's the UTC creation time of the .msi malware?

#### Cách làm 

- Mình tính SHA-256 của file 3CXDesktopApp-18.12.416.msi bằng Get-FileHash.

<img width="1471" height="243" alt="image" src="https://github.com/user-attachments/assets/a26aafa9-adca-4a5e-8fa1-714d3dc8e1f4" />


- Sau đó tra hash trên VirusTotal và xem mục History.

<img width="692" height="233" alt="image" src="https://github.com/user-attachments/assets/a29816e2-197c-49a4-abad-3fd689972e5b" />

#### Kết luận:
- Thời gian tạo file .msi (UTC) là 2023-03-13 06:33:26 UTC

<img width="995" height="196" alt="image" src="https://github.com/user-attachments/assets/866885d2-2bf8-4e51-a583-47c8763b7774" />

### Câu 3: Executable files (.exe) are frequently used as primary or secondary malware payloads, while dynamic link libraries (.dll) often load malicious code or enhance malware functionality. Analyzing files deposited by the Microsoft Software Installer (.msi) is crucial for identifying malicious files and investigating their full potential. Which malicious DLLs were dropped by the .msi file?

#### Cách làm:
- Mình tiếp dùng VirusTotal và xem nhóm Bundled Files.

<img width="1608" height="477" alt="image" src="https://github.com/user-attachments/assets/14b2ed19-cd54-4982-b882-e0257fcf03cf" />

- Mình thấy được chỉ có hai DLL bị gắn cờ nặng: ffmpeg.dll (54/70) và d3dcompiler_47.dll (43/70).


#### Kết luận:
- Hai DLL độc hại do .msi thả ra là ffmpeg.dll và d3dcompiler_47.dll.

<img width="1000" height="262" alt="image" src="https://github.com/user-attachments/assets/1f8ac931-9a9a-4e82-a652-b4c7bdb030b7" />

### Câu 4: Recognizing the persistence techniques used in this incident is essential for current mitigation strategies and future defense improvements. What is the MITRE Technique ID employed by the .msi files to load the malicious DLL?

#### Cách làm 

- Mình tìm hiểu cách bộ cài 3CX nạp DLL độc hại. File 3CXDesktopApp.exe là file hợp lệ, khi chạy nó tự nạp các DLL nằm cùng thư mục, nên kẻ tấn công thay ffmpeg.dll bằng bản độc hại để được nạp theo.
- Tên kỹ thuật này trên trang MITRE ATT&CK là T1574 Hijack Execution Flow

#### Kết luận 

- MITRE Technique ID là T1574.

### Câu 5: Recognizing the malware type (threat category) is essential to your investigation, as it can offer valuable insight into the possible malicious actions you'll be examining. What is the threat category of the two malicious DLLs?

#### Cách làm
- Trên VirusTotal, khi xem chi tiết hai file ffmpeg.dll và d3dcompiler_47.dll, sẽ thấy phần phân loại mối đe dọa dựa trên hành vi và nhãn dán từ các engine diệt virus.

- Phần lớn các nhà cung cấp bảo mật (Security vendors' analysis) đều đồng loạt nhận diện đây là mã độc cửa hậu thuộc họ Trojan.

<img width="1896" height="908" alt="image" src="https://github.com/user-attachments/assets/342e4b17-18e6-4328-86d9-6f28c7650e0d" />


#### Kết luận 

- Phân loại mối đe dọa (Threat category) của hai DLL này là: Trojan

<img width="1006" height="237" alt="image" src="https://github.com/user-attachments/assets/7e9576e4-1c7a-4da9-a097-b02fd4c76486" />

### Câu 6: As a threat intelligence analyst conducting dynamic analysis, it's vital to understand how malware can evade detection in virtualized environments or analysis systems. This knowledge will help you effectively mitigate or address these evasive tactics. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?

#### Cách làm 

- Mình tiếp tục dùng kết quả phân tích của tệp d3dcompiler_47.dll hoặc ffmpeg.dll trên giao diện VirusTotal.
- Sau đó xem BEHAVIOR để xem báo cáo phân tích động từ các môi trường sandbox.
- Trong danh sách báo cáo, ở cả hai nhóm chiến thuật là Stealth và Discovery, hệ thống đều ghi nhận rõ ràng một kỹ thuật có tên là Virtualization/Sandbox Evasion (T1497).

<img width="1795" height="731" alt="image" src="https://github.com/user-attachments/assets/7a5d39ea-411b-4847-8649-58f376732cea" />


#### Kết luận 

- MITRE ID cho kỹ thuật trốn tránh ảo hóa/sandbox là: T1497

<img width="1005" height="260" alt="image" src="https://github.com/user-attachments/assets/6e7d35e6-cf02-4279-a4d7-7549ad907dce" />

### Câu 7: When conducting malware analysis and reverse engineering, understanding anti-analysis techniques is vital to avoid wasting time. Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?

#### Cách làm 

- Mình tiếp tục phân tích tệp ffmpeg.dll trên giao diện VirusTotal.   

- Sau đó mình đi sâu vào chi tiết của nhóm kỹ thuật Virtualization/Sandbox Evasion (T1497).
- Ở mục System Checks hệ thống tự động trích xuất và hiển thị rõ ràng các dấu hiệu phát hiện môi trường ảo hóa mà đoạn mã độc thực thi chính là VMWare

<img width="640" height="282" alt="image" src="https://github.com/user-attachments/assets/fe0bb903-2e6e-4104-9d90-329ea63f9aac" />
 
#### Kết luận

- Hypervisor bị nhắm mục tiêu bởi các kỹ thuật anti-analysis là: VMware

<img width="986" height="231" alt="image" src="https://github.com/user-attachments/assets/ee53650d-a211-40e9-823c-6cb93a222a54" />

### Câu 8: Identifying the cryptographic method used in malware is crucial for understanding the techniques employed to bypass defense mechanisms and execute its functions fully. What encryption algorithm is used by the ffmpeg.dll file?

#### Cách làm.

- Mình tiếp tục rà soát danh sách các kỹ thuật MITRE ATT&CK trên giao diện VirusTotal.

- Để tìm hiểu về cách mã độc mã hóa và che giấu dữ liệu, mình tập trung vào nhóm chiến thuật Stealth và xem xét kỹ thuật Obfuscated Files or Information.

- Phần mô tả chi tiết của kỹ thuật chỉ ra rõ ràng cách thức mã độc che giấu payload. Hệ thống phát hiện tệp ffmpeg.dll có chứa các đoạn mã liên quan đến thuật toán RC4 KSA

<img width="1411" height="877" alt="image" src="https://github.com/user-attachments/assets/675c013f-081d-4b21-98dd-c274167146a9" />


#### Kết luận

- Thuật toán mã hóa được sử dụng là: RC4

<img width="995" height="225" alt="image" src="https://github.com/user-attachments/assets/9f5aa768-0d88-4b14-9822-51b356fe6829" />


### Câu 9: As an analyst, you've recognized some TTPs involved in the incident, but identifying the APT group responsible will help you search for their usual TTPs and uncover other potential malicious activities. Which group is responsible for this attack?

#### Cách làm

- Mình thực hiện tra cứu các báo cáo tình báo mối đe dọa về sự cố 3CX DesktopApp từ các hãng bảo mật uy tín bằng từ khóa như "3CX supply chain attack threat actor attribution" thì tìm hiểu được nhóm APT chịu trách nhiệm cho cuộc tấn công này là: Lazarus

### Kết luận
- Nhóm APT chịu trách nhiệm cho cuộc tấn công này là: Lazarus

<img width="1011" height="252" alt="image" src="https://github.com/user-attachments/assets/cdc881c0-792e-489a-97be-d1c3c66733bc" />

