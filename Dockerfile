FROM python:3.11

WORKDIR /app

#системные зависимости для сборки netifaces
RUN apt-get update && apt-get install -y \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

#python-зависимости
RUN pip install --no-cache-dir flask scapy netifaces

COPY . .


USER root


EXPOSE 5000

CMD ["python", "app.py"]
