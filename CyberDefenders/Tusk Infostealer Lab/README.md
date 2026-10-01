# Tusk Infostealer Lab

## 1. Bối cảnh 

Bài Lab mô phỏng một chiến dịch tấn công nhắm vào tổ chức phát triển blockchain. Điểm nổ của sự cố là khi một nhân viên truy cập vào trang web giả mạo nền tảng quản lý DAO, dẫn đến việc tải nhầm mã độc và khiến hàng loạt ví tiền điện tử bị rút cạn. Quá trình điều tra đòi hỏi việc phân tích các báo cáo tình báo bảo mật để trích xuất IOCs, làm rõ TTPs và truy vết hạ tầng của tin tặc.

## 2. Điều tra 

### Câu 1: In KB, what is the size of the malicious file?

#### Cách làm: 

- Mình tra cứu mã hash của mẫu mã độc ban đầu trên VirusTotal và tìm được kích thước chính xác là 921.36

<img width="1777" height="387" alt="image" src="https://github.com/user-attachments/assets/fe9ecfb3-8994-4c53-b5ca-2704e6df4131" />

### Câu 2: What word do the threat actors use in log messages to describe their victims, based on the name of an ancient hunted creature?

#### Cách làm 

- Mình tìm hiểu các báo cáo tình báo bảo mật về chiến dịch Tusk và đọc được một đoạn phân tích về ngôn ngữ của kẻ tấn công. nhóm tin tặc nói tiếng Nga này sử dụng từ lóng "Mammoth" để gọi các nạn nhân của chúng. Từ này vốn là tên của loài voi ma mút cổ đại.

#### Kết luận

- Từ được kẻ tấn công sử dụng là: Mammoth

### Câu 3: The threat actor set up a malicious website to mimic a platform designed for creating and managing decentralized autonomous organizations (DAOs) on the MultiversX blockchain (peerme.io). What is the name of the malicious website the attacker created to simulate this platform?

#### Cách làm 

- Mình tiếp tục tìm thông tin trên trang web đó thì tim ra tên của trang web giả mạo là: tidyme.io

<img width="1010" height="226" alt="image" src="https://github.com/user-attachments/assets/dbc4372a-3e94-423c-96b0-7e269e5b0b0c" />

### Câu 4: Which cloud storage service did the campaign operators use to host malware samples for both macOS and Windows OS versions?

#### Cách làm 

- Báo cáo chỉ rõ rằng chiến dịch này sử dụng nhiều mẫu mã độc nhắm vào cả hai hệ điều hành macOS và Windows, và tất cả chúng đều được lưu trữ trên nền tảng Dropbox để phát tán

<img width="901" height="95" alt="image" src="https://github.com/user-attachments/assets/883e8fca-0106-4d7d-867c-d7c40a63ce8c" />

#### Kết luận 

- Dịch vụ đám mây được sử dụng là: Dropbox

<img width="1007" height="195" alt="image" src="https://github.com/user-attachments/assets/e17cf3f6-52ef-45ba-8ffe-1d7727e6d830" />

### Câu 5: The malicious executable contains a configuration file that includes base64-encoded URLs and a password used for archived data decompression, enabling the download of second-stage payloads. What is the password for decompression found in this configuration file?

#### Cách làm 

- Báo cáo tiếp tục hiển thị trực tiếp nội dung của tệp cấu hình config.json. Nhìn vào đoạn mã này sẽ phát hiện trường "password" chứa mật khẩu dùng để giải nén dữ liệu.

<img width="917" height="345" alt="image" src="https://github.com/user-attachments/assets/d634d9a2-4539-4f8b-af30-d6e290c39a13" />

#### Kết luận

- Mật khẩu giải nén là: newfile2024

<img width="1012" height="235" alt="image" src="https://github.com/user-attachments/assets/02033b61-e733-448d-9548-049f805724fb" />

### Câu 6: What is the name of the function responsible for retrieving the field archive from the configuration file?

#### Cách làm:

- Báo cáo tiếp tục ghi chú rất rõ ràng: hàm downloadAndExtractArchive chịu trách nhiệm trích xuất trường archive từ tệp cấu hình để lấy đường link Dropbox, sau đó tải và giải nén tệp chứa mã độc.

 <img width="887" height="210" alt="image" src="https://github.com/user-attachments/assets/41941cb2-c66c-4b2d-afc2-9fb14f13bedd" />

 #### Kết luận 

 - Tên hàm là: downloadAndExtractArchive

<img width="1001" height="171" alt="image" src="https://github.com/user-attachments/assets/9260e7ba-dff7-448e-8570-e4a45823d7c3" />

### Câu 7: In the third sub-campaign carried out by the operators, the attacker mimicked an AI translator project. What is the name of the legitimate translator, and what is the name of the malicious translator created by the attackers?

#### Cách làm 

- Báo cáo tiếp tục nêu rõ ở chiến dịch này, nhóm tin tặc đã giả mạo một dự án dịch thuật AI tên là YOUS. Tên miền của trang web hợp pháp là yous.ai, trong khi trang web độc hại được chúng dựng lên là voico.io

 <img width="892" height="145" alt="image" src="https://github.com/user-attachments/assets/4b8274d3-27f4-4f6c-9e79-3461738ffaab" />

#### Kết luận 

- Trang web hợp pháp và trang web giả mạo lần lượt là: yous.ai, voico.io

<img width="995" height="228" alt="image" src="https://github.com/user-attachments/assets/25cdfa59-6aad-4b6b-be42-9cb04da7d1c8" />

### Câu 8: The downloader is tasked with delivering additional malware samples to the victim’s machine, primarily infostealers like StealC and Danabot. What are the IP addresses of the StealC C2 servers used in the campaign?

#### Cách làm:

- Báo cáo tiếp tục chỉ ra các địa chỉ IP được phân loại là máy chủ điều khiển và ra lệnh dành riêng cho mã độc StealC.

<img width="832" height="496" alt="image" src="https://github.com/user-attachments/assets/476b5c00-c201-4f16-b12d-a3b04f32f8cd" />

#### Kết luận 

- Các địa chỉ IP của StealC C2 là: 46.8.238.240, 23.94.225.177

<img width="1002" height="227" alt="image" src="https://github.com/user-attachments/assets/110a31cd-e142-4bb3-8004-752065072977" />


### Câu 9: What is the address of the Ethereum cryptocurrency wallet used in this campaign?


#### Cách làm 

- Mình tiếp tục kiểm tra bảng tổng hợp địa chỉ ví tiền điện tử (Cryptocurrency wallet addresses) ở phần cuối báo cáo và thấy rằng Địa chỉ ví Ethereum là: 0xaf0362e215Ff4e004F30e785e822F7E20b99723A

<img width="1002" height="185" alt="image" src="https://github.com/user-attachments/assets/1878a05f-6c34-4c53-9143-8bed2ab3ca9e" />
 
