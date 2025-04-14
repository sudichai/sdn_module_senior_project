FROM python:3.9

WORKDIR /app

COPY . /app

COPY requirements.txt .

RUN pip install ryu pandas joblib mysql-connector-python paramiko 

RUN pip install -r requirements.txt

CMD ["ryu-manager", "main/simple_switch.py"]
