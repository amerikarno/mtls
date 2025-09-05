# File structure
<!-- 
/etc/nginx/tls/
  ca.crt                 # Root/Intermediate CA ที่ใช้ตรวจ client
  server.crt             # ใบรับรองเซิร์ฟเวอร์ (รวม chain ถ้ามี) = fullchain
  server.key             # กุญแจส่วนตัวเซิร์ฟเวอร์ (สิทธิ์ 600)

/opt/mtls/
  ca/
    ca.key
    ca.crt
  server/
    server.key
    server.csr
    server.crt
    server.ext
  client/
    client.key
    client.csr
    client.crt
    client.ext
    client.p12 (ถ้าต้องแจกให้ผู้ใช้แบบไฟล์เดียว) 
-->

# Create Root CA
<!-- 

# กุญแจ CA (ใส่รหัสผ่านก็ได้ แต่ต้องปลดก่อนใส่ Nginx)
openssl genrsa -out ca.key 4096

# ออกใบรับรอง Root CA (ปรับ CN/Org ตามจริง)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=TH/ST=Bangkok/O=Example Co.,Ltd./CN=Example Root CA" 
-->

# create Server Certificate (must have SAN)
<!-- 

# สร้าง key
openssl genrsa -out server.key 2048

# สร้าง CSR (ปรับ CN เป็นโดเมนจริง)
openssl req -new -key server.key -out server.csr \
  -subj "/C=TH/ST=Bangkok/O=Example Co.,Ltd./CN=your.domain.com"

# สร้างไฟล์ extension ระบุ SAN + EKU สำหรับ server
cat > server.ext <<'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = your.domain.com         # โดเมนจริง
DNS.2 = www.your.domain.com     # โดเมนรอง (ถ้ามี)
IP.1  = 10.0.0.10               # IP (ถ้าต้องเข้าตรง IP)
EOF

# เซ็นด้วย Root CA
openssl x509 -req -in server.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key \
  -CAcreateserial -out server.crt -days 825 -sha256 -extfile server.ext

# ตรวจสอบ
openssl x509 -in server.crt -noout -text | grep -A2 "X509v3 Subject Alternative Name" 
-->

# create Client Certificate (with EKU: clientAuth)
<!-- 

# key ฝั่ง client
openssl genrsa -out client.key 2048

# CSR (ใส่ CN เป็นชื่อผู้ใช้/บริการ)
openssl req -new -key client.key -out client.csr \
  -subj "/C=TH/ST=Bangkok/O=Example Co.,Ltd./CN=client-001"

# ไฟล์ extension สำหรับ client
cat > client.ext <<'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# เซ็นด้วย CA
openssl x509 -req -in client.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key \
  -CAcreateserial -out client.crt -days 825 -sha256 -extfile client.ext

# (ทางเลือก) แพ็กเป็น .p12 เพื่อแจกผู้ใช้ (จะถามรหัสผ่าน)
openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12 \
  -name "client-001" 
  -->
