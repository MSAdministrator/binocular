# Base builder layer
FROM python:3.8 as builder

RUN pip install --user --upgrade pip
ENV TZ="America/Chicago"

# VirusTotal Service
FROM python:3.8 as VTService
ENV TZ="America/Chicago"
WORKDIR /
RUN pip install --upgrade pip
RUN pip install vt-py

COPY ./containers/virustotal.py virustotal.py
