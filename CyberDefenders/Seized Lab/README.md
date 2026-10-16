# Seized Lab
## Bối cảnh 

Bài Lab cung cấp các bản chụp bộ nhớ (memory snapshot) của một máy chủ Linux CentOS bị nghi ngờ đã bị tấn công. Nhiệm vụ của mình là đóng vai chuyên gia blue team: dùng Volatility cùng profile CentOS 7 (kernel 3.10.0-1062) đi kèm để phân tích memory, từ đó xác định chi tiết cuộc tấn công, gồm thông tin hệ thống, tiến trình, kết nối mạng và các hành vi của kẻ tấn công.

## Q1: What is the CentOS version installed on the machine?

- Đề cung cấp profile `Centos7.3.10.1062`, tên profile cho biết hệ điều hành là CentOS 7 với kernel `3.10.0-1062`.

<img width="411" height="73" alt="image" src="https://github.com/user-attachments/assets/19c83de1-1e4a-499c-9d31-24617aab31fb" />

- Mình đối chiếu số kernel này với bảng phiên bản CentOS thì thấy kernel 3.10.0-1062 thuộc bản CentOS 7.7.1908 (phát hành tháng 8/2019, dựa trên RHEL 7.7)

- Để xác nhận, mình tìm chuỗi `CentOS Linux release` trong memory dump bằng `strings` và `grep` và kết quả chính xác là CentOS 7.7.1908

<img width="937" height="126" alt="image" src="https://github.com/user-attachments/assets/4f671e9c-5279-44bc-b1e9-5a1cb0822de5" />


## Q2: There is a command containing a strange message in the bash history. Will you be able to read it?

