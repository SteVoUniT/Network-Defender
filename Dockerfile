#I didnt add a Node server if you need node just do node:24-alpine
# Since We are readding Flask ill reopen ports
FROM alpine:latest
WORKDIR /Network-Defender
COPY . .
RUN apk add --no-cache python3 py3-pip tshark
RUN pip install --break-system-packages -r requirements.txt
EXPOSE 5000
CMD ["python", "server.py"]
