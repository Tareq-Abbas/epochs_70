# start by pulling the python image
FROM python:3.8-slim-buster

WORKDIR /rdds

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libglib2.0-0 && \
    rm -rf /var/lib/apt/lists/*


COPY . .
# adding environment variables to the image
ENV FLASK_APP=rdds.py
ENV EMAIL_PASS="iuzpbayifmamuzlx"
ENV EMAIL_USER="nagem2.dergham@gmail.com"
ENV SECRET_KEY="f5a389b707cb442d88a81e97bb243b1080781838420cd15c05323965b938ed57"

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
