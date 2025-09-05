# ใช้ base image เป็น nginx official
FROM nginx:1.27-alpine

# ลบ default config ถ้าไม่ต้องการใช้
# RUN rm /etc/nginx/conf.d/default.conf

# copy config file จาก local ไปยัง container
# สมมติว่ามีไฟล์ nginx.conf และ conf.d/myapp.conf
COPY ./nginx.conf /etc/nginx/nginx.conf
# COPY ./conf.d/ /etc/nginx/conf.d/
COPY ./index.html /usr/share/nginx/html/index.html

# copy static files (เช่น React build หรือ HTML) ไปไว้ที่ nginx html root
# สมมติว่ามีโฟลเดอร์ dist/ จากการ build frontend
# COPY ./dist/ /usr/share/nginx/html/

# copy ca cert, server cert, and server key
COPY ./mtls/client/ca/ca.crt /etc/nginx/tls/ca.crt
COPY ./mtls/server/server.crt /etc/nginx/tls/server.crt
COPY ./mtls/server/server.key /etc/nginx/tls/server.key
RUN chmod 600 /etc/nginx/tls/server.key

# expose port 80
EXPOSE 443

# run nginx แบบ foreground
CMD ["nginx", "-g", "daemon off;"]